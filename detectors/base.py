"""检测器插件抽象基类与注册器（项目文档 6.1 插件化架构）"""


class BaseDetector:
    """漏洞检测器抽象基类。

    所有检测能力实现为独立子类，并实现 detect(contract_info) 方法；
    返回统一漏洞列表：[{
        "vul_type": str,       # 漏洞类型
        "risk_level": str,     # 高危/中危/低危
        "location": str,       # 位置（行号/函数名）
        "description": str,    # 漏洞描述
        "suggestion": str,     # 修复建议
    }]
    """
    name = "base"
    description = ""

    def detect(self, contract_info: dict) -> list:
        raise NotImplementedError


_registry = []


def register(cls):
    """检测器注册装饰器：@register 后实例加入注册器，审计时统一调度"""
    _registry.append(cls())
    return cls


def get_detectors() -> list:
    """获取全部已注册检测器实例"""
    return list(_registry)
