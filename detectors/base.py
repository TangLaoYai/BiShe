"""检测器插件抽象基类与注册器（项目文档 6.1 插件化架构）"""


class BaseDetector:
    """漏洞检测器抽象基类。

    所有检测能力实现为独立子类，并实现 detect(contract_info) 方法；
    返回统一漏洞列表：[{
        "vul_type": str,       # 漏洞类型
        "risk_level": str,     # 高危/中危/低危
        "confidence": str,     # 检测置信度：高/中/低（区分规则确定性与启发式推断）
        "location": str,       # 位置（行号/函数名）
        "description": str,    # 漏洞描述
        "suggestion": str,     # 修复建议
    }]

    confidence 说明：
    - 高：规则可确定命中（如 tx.origin、selfdestruct、硬编码私钥），误报概率低
    - 中：启发式推断（如未授权访问、参数边界缺失），需人工复核上下文
    - 低：弱信号提示（如时间戳依赖），仅供参考
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
