from enum import Enum

class SimaPayloadType(str, Enum):
    Register = "Register"
    Auth = "Auth"
    Sign = "Sign"