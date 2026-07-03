# -*- coding: utf-8 -*-
"""
Auth Token 提取

从 SampleData.samples (List<String>) 中正则提取 Authorization 头。

V10.0 源码实证 (ZAP-Bridge):
    SampleData._id 类型为 Key.java (com.akto.dto.traffic.Key)
    Key 字段: apiCollectionId / url / method / responseCode / bucketStartEpoch / bucketEndEpoch
    不存在 apiInfoKey 和 timestamp 字段。
"""
import re
import logging

logger = logging.getLogger("nuclei-bridge")


def fetch_latest_token_regex(db, collection_id: int, url: str, method: str) -> str:
    """
    从 SampleData 中正则提取 Authorization 头。

    Args:
        db: MongoDB database 对象
        collection_id: API Collection ID
        url: API URL
        method: HTTP 方法

    Returns:
        Auth Token 值（如 "Bearer xxx"），无则返回 None
    """
    query_filter = {
        "_id.apiCollectionId": collection_id,
        "_id.url": url,
        "_id.method": method,
    }
    sample_doc = db.SampleData.find_one(
        query_filter, sort=[("_id.bucketStartEpoch", -1)]
    )
    if not sample_doc or not sample_doc.get("samples"):
        return None

    for sample in sample_doc["samples"]:
        match = re.search(r'Authorization:\s*(\S+)', sample)
        if match:
            return match.group(1)
    return None
