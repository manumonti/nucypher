from typing import Any, List, Optional

from marshmallow import fields, post_load, validate

from nucypher.policy.conditions.evm import RPCCondition
from nucypher.policy.conditions.exceptions import InvalidCondition
from nucypher.policy.conditions.lingo import ConditionType, ReturnValueTest
from nucypher.policy.conditions.utils import CamelCaseSchema


class TimeCondition(RPCCondition):
    METHOD = "blocktime"
    CONDITION_TYPE = ConditionType.TIME.value

    class Schema(CamelCaseSchema):
        SKIP_VALUES = (None,)
        condition_type = fields.Str(
            validate=validate.Equal(ConditionType.TIME.value), required=True
        )
        name = fields.Str(required=False)
        chain = fields.Int(required=True)
        method = fields.Str(dump_default="blocktime", required=True)
        return_value_test = fields.Nested(
            ReturnValueTest.ReturnValueTestSchema(), required=True
        )

        @post_load
        def make(self, data, **kwargs):
            return TimeCondition(**data)

    def __repr__(self) -> str:
        r = f"{self.__class__.__name__}(timestamp={self.return_value_test.value}, chain={self.chain})"
        return r

    def __init__(
        self,
        return_value_test: ReturnValueTest,
        chain: int,
        method: str = METHOD,
        condition_type: str = CONDITION_TYPE,
        name: Optional[str] = None,
    ):
        if method != self.METHOD:
            raise InvalidCondition(
                f"{self.__class__.__name__} must be instantiated with the {self.METHOD} method."
            )
        super().__init__(
            chain=chain,
            method=method,
            return_value_test=return_value_test,
            name=name,
            condition_type=condition_type,
        )

    def validate_method(self, method):
        return method

    @property
    def timestamp(self):
        return self.return_value_test.value

    def _execute_call(self, parameters: List[Any]) -> Any:
        """Execute onchain read and return result."""
        # TODO may need to rethink as part of #3051 (multicall work).
        latest_block = self.w3.eth.get_block("latest")
        return latest_block.timestamp
