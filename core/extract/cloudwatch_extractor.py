import logging
import tempfile
import sys
import datetime
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import common.aws_service as aws_service_helper
from core.extract.extract_parser import parse_log_from_entries

logger = logging.getLogger("WorkloadReplicatorLogger")


class CloudwatchExtractor:
    config = None

    def __init__(self, config):
        self.config = config

    def get_extract_from_cloudwatch(self, start_time, end_time):
        cloudwatch_logs = []
        if self.config.get("source_cluster_endpoint"):
            logger.info(
                f"Extracting logs from source cluster endpoint: {self.config['source_cluster_endpoint']}"
            )
            source_cluster_endpoint = self.config.get("source_cluster_endpoint")
            region = source_cluster_endpoint.split(".")[2]
            endpoint = source_cluster_endpoint.split(".")[0]
            response = aws_service_helper.cw_describe_log_groups(region=region)
            cloudwatch_logs = self._read_cloudwatch_logs(
                response, endpoint, start_time, end_time, region
            )
        elif self.config.get("log_location"):
            logger.info(f"Extracting logs for {self.config['log_location']}")
            response = aws_service_helper.cw_describe_log_groups(
                log_group_name=self.config.get("log_location"),
                region=self.config.get("region"),
            )
            for log_group in response["logGroups"]:
                log_group_name = log_group["logGroupName"]
                response_stream = aws_service_helper.cw_describe_log_streams(
                    log_group_name, self.config.get("region")
                )
                endpoint = response_stream["logStreams"][0]["logStreamName"]
                cloudwatch_logs = self._read_cloudwatch_logs(
                    response, endpoint, start_time, end_time, self.config.get("region")
                )
        else:
            logger.error(
                "For Cloudwatch Log Extraction, one of source_cluster_endpoint or log_location must be provided"
            )
            sys.exit(-1)
        return cloudwatch_logs

    def _read_cloudwatch_logs(self, response, endpoint, start_time, end_time, region):
        connections = {}
        last_connections = {}
        logs = {}
        databases = set()
        for log_group in response["logGroups"]:
            log_group_name = log_group["logGroupName"]
            stream_batch = aws_service_helper.cw_describe_log_streams(
                log_group_name=log_group_name, region=region
            )["logStreams"]
            for stream in stream_batch:
                stream_name = stream["logStreamName"]
                if endpoint == stream_name:
                    logger.info(
                        f"Extracting for log group: {log_group_name} between time {start_time} and {end_time}"
                    )

                    if "useractivitylog" in log_group_name:
                        log_type = "useractivitylog"
                    elif "connectionlog" in log_group_name:
                        log_type = "connectionlog"
                    else:
                        logger.warning(
                            f"Unsupported log file {log_group_name}, cannot determine type"
                        )
                        continue

                    self._read_and_parse_logs(log_group_name, stream_name, start_time, end_time, region, log_type,
                                              connections, last_connections, logs, databases)

        return connections, logs, databases, last_connections

    def _parse_logs(self, connections, databases, end_time, last_connections, log_type, logs, start_time,
                    log_entries):
        if log_type == "connectionlog":
            logger.info("Parsing connection logs...%s %s %s", repr(databases), start_time, end_time)
            parse_log_from_entries(
                log_entries,
                "connectionlog.gz",
                connections,
                last_connections,
                logs,
                databases,
                start_time,
                end_time,
            )
        if log_type == "useractivitylog":
            logger.info("Parsing user activity logs...%s %s %s", repr(databases), start_time, end_time)
            parse_log_from_entries(
                log_entries,
                "useractivitylog.gz",
                connections,
                last_connections,
                logs,
                databases,
                start_time,
                end_time,
            )

    def _read_and_parse_logs(self, log_group_name, log_stream_name, start_time, end_time, region, log_type, connections,
                             last_connections, logs, databases):
        logger.info("_read_and_parse_logs reading Cloudwatch logs and parsing %s %s %s %s %s", log_group_name, log_stream_name, start_time, end_time, repr(databases))
        cloudwatch_client = boto3.client("logs", region)
        paginator = cloudwatch_client.get_paginator("filter_log_events")
        pagination_config = {"MaxItems": 10000}
        convert_to_millis_since_epoch = (
            lambda time: int(
                (time.replace(tzinfo=None) - datetime.datetime.utcfromtimestamp(0)).total_seconds()
            )
                         * 1000
        )
        start_time_millis_since_epoch = convert_to_millis_since_epoch(start_time)
        end_time_millis_since_epoch = convert_to_millis_since_epoch(end_time)
        response_iterator = paginator.paginate(
            logGroupName=log_group_name,
            logStreamNames=[log_stream_name],
            startTime=start_time_millis_since_epoch,
            endTime=end_time_millis_since_epoch,
            PaginationConfig=pagination_config,
        )
        next_token = None
        while next_token != "":
            for response in response_iterator:
                next_token = response.get("nextToken", "")
                for event in response["events"]:
                    self._parse_logs(connections, databases, end_time, last_connections, log_type, logs, start_time,
                                     event["message"])
            pagination_config.update({"StartingToken": next_token})
            response_iterator = paginator.paginate(
                logGroupName=log_group_name,
                logStreamNames=[log_stream_name],
                startTime=start_time_millis_since_epoch,
                endTime=end_time_millis_since_epoch,
                PaginationConfig=pagination_config,
            )
