"""漏洞检测器插件包

插件化架构（项目文档 6.1）：
- BaseDetector：统一检测器接口，detect(contract_info) 返回漏洞列表
- DetectorRegistry：检测器注册器，新增检测能力只需新增子类并 @register 注册
- 审计执行时遍历全部已注册检测器，汇总结果统一入库
"""
from .base import BaseDetector, register, get_detectors
from .slither_detector import SlitherDetector      # noqa: F401 注册静态扫描
from .auth_detector import AuthDetector            # noqa: F401 注册接口权限检测
from .fuzz_detector import BoundaryFuzzDetector    # noqa: F401 注册边界Fuzz检测

__all__ = ["BaseDetector", "register", "get_detectors",
           "SlitherDetector", "AuthDetector", "BoundaryFuzzDetector"]
