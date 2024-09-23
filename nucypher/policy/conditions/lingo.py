import ast
import base64
import json
import operator as pyoperator
from abc import abstractmethod
from enum import Enum
from hashlib import md5
from typing import Any, Dict, List, Optional, Set, Tuple, Type, Union

from hexbytes import HexBytes
from marshmallow import (
    Schema,
    ValidationError,
    fields,
    post_load,
    pre_load,
    validate,
    validates,
    validates_schema,
)
from marshmallow.validate import OneOf, Range
from packaging.version import parse as parse_version
from web3 import HTTPProvider

from nucypher.policy.conditions.base import (
    AccessControlCondition,
    ExecutionCall,
    MultiConditionAccessControl,
    _Serializable,
)
from nucypher.policy.conditions.context import (
    _resolve_context_variable,
    is_context_variable,
)
from nucypher.policy.conditions.exceptions import (
    InvalidCondition,
    InvalidConditionLingo,
    ReturnValueEvaluationError,
)
from nucypher.policy.conditions.types import ConditionDict, Lingo
from nucypher.policy.conditions.utils import CamelCaseSchema


class _ConditionField(fields.Dict):
    """Serializes/Deserializes Conditions to/from dictionaries"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _serialize(self, value, attr, obj, **kwargs):
        return value.to_dict()

    def _deserialize(self, value, attr, data, **kwargs):
        lingo_version = self.context.get("lingo_version")
        condition_data = value
        condition_class = ConditionLingo.resolve_condition_class(
            condition=condition_data, version=lingo_version
        )
        instance = condition_class.from_dict(condition_data)
        return instance


# CONDITION = TIME | CONTRACT | RPC | JSON_API | COMPOUND | SEQUENTIAL
class ConditionType(Enum):
    """
    Defines the types of conditions that can be evaluated.
    """

    TIME = "time"
    CONTRACT = "contract"
    RPC = "rpc"
    JSONAPI = "json-api"
    COMPOUND = "compound"
    SEQUENTIAL = "sequential"

    @classmethod
    def values(cls) -> List[str]:
        return [condition.value for condition in cls]


class CompoundAccessControlCondition(MultiConditionAccessControl):
    """
    A combination of two or more conditions connected by logical operators such as AND, OR, NOT.

    CompoundCondition grammar:
        OPERATOR = AND | OR | NOT

        COMPOUND_CONDITION = {
            "name": ...  (Optional)
            "conditionType": "compound",
            "operator": OPERATOR,
            "operands": [CONDITION*]
        }
    """
    AND_OPERATOR = "and"
    OR_OPERATOR = "or"
    NOT_OPERATOR = "not"

    OPERATORS = (AND_OPERATOR, OR_OPERATOR, NOT_OPERATOR)
    CONDITION_TYPE = ConditionType.COMPOUND.value

    @classmethod
    def _validate_operator_and_operands(
        cls,
        operator: str,
        operands: List[Union[Dict, AccessControlCondition]],
        exception_class: Union[Type[ValidationError], Type[InvalidCondition]],
    ):
        if operator not in cls.OPERATORS:
            raise exception_class(f"{operator} is not a valid operator")

        num_operands = len(operands)
        if operator == cls.NOT_OPERATOR:
            if num_operands != 1:
                raise exception_class(
                    f"Only 1 operand permitted for '{operator}' compound condition"
                )
        elif num_operands < 2:
            raise exception_class(
                f"Minimum of 2 operand needed for '{operator}' compound condition"
            )
        elif num_operands > cls.MAX_NUM_CONDITIONS:
            raise exception_class(
                f"Maximum of {cls.MAX_NUM_CONDITIONS} operands allowed for '{operator}' compound condition"
            )


    class Schema(AccessControlCondition.Schema):
        condition_type = fields.Str(
            validate=validate.Equal(ConditionType.COMPOUND.value), required=True
        )
        operator = fields.Str(required=True)
        operands = fields.List(_ConditionField, required=True)

        # maintain field declaration ordering
        class Meta:
            ordered = True

        @validates_schema
        def validate_operator_and_operands(self, data, **kwargs):
            operator = data["operator"]
            operands = data["operands"]
            CompoundAccessControlCondition._validate_operator_and_operands(
                operator, operands, ValidationError
            )

        @post_load
        def make(self, data, **kwargs):
            return CompoundAccessControlCondition(**data)

    def __init__(
        self,
        operator: str,
        operands: List[AccessControlCondition],
        condition_type: str = CONDITION_TYPE,
        name: Optional[str] = None,
    ):
        """
        COMPOUND_CONDITION = {
            "operator": OPERATOR,
            "operands": [CONDITION*]
        }
        """
        self._validate_operator_and_operands(operator, operands, InvalidCondition)

        self.operator = operator
        self.operands = operands
        self.condition_type = condition_type
        self.name = name
        self.id = md5(bytes(self)).hexdigest()[:6]

        super().__init__(condition_type=condition_type, name=name)

    def __repr__(self):
        return f"Operator={self.operator} (NumOperands={len(self.operands)}), id={self.id})"

    def verify(self, *args, **kwargs) -> Tuple[bool, Any]:
        values = []
        overall_result = True if self.operator == self.AND_OPERATOR else False
        for condition in self.operands:
            current_result, current_value = condition.verify(*args, **kwargs)
            values.append(current_value)
            if self.operator == self.AND_OPERATOR:
                overall_result = overall_result and current_result
                # short-circuit check
                if overall_result is False:
                    break
            elif self.operator == self.OR_OPERATOR:
                overall_result = overall_result or current_result
                # short-circuit check
                if overall_result is True:
                    break
            else:
                # NOT_OPERATOR
                return not current_result, current_value

        return overall_result, values

    @property
    def conditions(self):
        return self.operands


class OrCompoundCondition(CompoundAccessControlCondition):
    def __init__(self, operands: List[AccessControlCondition]):
        super().__init__(operator=self.OR_OPERATOR, operands=operands)


class AndCompoundCondition(CompoundAccessControlCondition):
    def __init__(self, operands: List[AccessControlCondition]):
        super().__init__(operator=self.AND_OPERATOR, operands=operands)


class NotCompoundCondition(CompoundAccessControlCondition):
    def __init__(self, operand: AccessControlCondition):
        super().__init__(operator=self.NOT_OPERATOR, operands=[operand])


_COMPARATOR_FUNCTIONS = {
    "==": pyoperator.eq,
    "!=": pyoperator.ne,
    ">": pyoperator.gt,
    "<": pyoperator.lt,
    "<=": pyoperator.le,
    ">=": pyoperator.ge,
}


class ConditionVariable(_Serializable):
    class Schema(CamelCaseSchema):
        var_name = fields.Str(required=True)  # TODO: should this be required?
        condition = _ConditionField(required=True)

        @post_load
        def make(self, data, **kwargs):
            return ConditionVariable(**data)

    def __init__(self, var_name: str, condition: AccessControlCondition):
        self.var_name = var_name
        self.condition = condition


class SequentialAccessControlCondition(MultiConditionAccessControl):
    """
    A series of conditions that are evaluated in a specific order, where the result of one
    condition can be used in subsequent conditions.

    SequentialCondition grammar:
        CONDITION_VARIABLE = {
            "varName": STR,
            "condition": {
                CONDITION
            }
        }

        SEQUENTIAL_CONDITION = {
            "name": ...  (Optional)
            "conditionType": "sequential",
            "conditionVariables": [CONDITION_VARIABLE*]
        }
    """

    CONDITION_TYPE = ConditionType.SEQUENTIAL.value

    @classmethod
    def _validate_condition_variables(
        cls,
        condition_variables: List[Union[Dict, ConditionVariable]],
        exception_class: Union[Type[ValidationError], Type[InvalidCondition]],
    ):
        num_condition_variables = len(condition_variables)
        if num_condition_variables < 2:
            raise exception_class("At least two conditions must be specified")

        if num_condition_variables > cls.MAX_NUM_CONDITIONS:
            raise exception_class(
                f"Maximum of {cls.MAX_NUM_CONDITIONS} conditions are allowed"
            )

    class Schema(AccessControlCondition.Schema):
        condition_type = fields.Str(
            validate=validate.Equal(ConditionType.SEQUENTIAL.value), required=True
        )
        condition_variables = fields.List(
            fields.Nested(ConditionVariable.Schema(), required=True)
        )

        # maintain field declaration ordering
        class Meta:
            ordered = True

        @validates_schema
        def validate_condition_variables(self, data, **kwargs):
            condition_variables = data["condition_variables"]
            SequentialAccessControlCondition._validate_condition_variables(
                condition_variables, ValidationError
            )

        @post_load
        def make(self, data, **kwargs):
            return SequentialAccessControlCondition(**data)

    def __init__(
        self,
        condition_variables: List[ConditionVariable],
        condition_type: str = CONDITION_TYPE,
        name: Optional[str] = None,
    ):
        self._validate_condition_variables(
            condition_variables=condition_variables, exception_class=InvalidCondition
        )
        self.condition_variables = condition_variables
        super().__init__(condition_type=condition_type, name=name)

    def __repr__(self):
        r = f"{self.__class__.__name__}(num_condition_variables={len(self.condition_variables)})"
        return r

    # TODO - think about not dereferencing context but using a dict;
    #  may allows more freedom for params
    def verify(
        self, providers: Dict[int, Set[HTTPProvider]], **context
    ) -> Tuple[bool, Any]:
        values = []
        latest_success = False
        inner_context = dict(context)  # don't modify passed in context - use a copy
        # resolve variables
        for condition_variable in self.condition_variables:
            latest_success, result = condition_variable.condition.verify(
                providers=providers, **inner_context
            )
            values.append(result)
            if not latest_success:
                # short circuit due to failed condition
                break

            inner_context[f":{condition_variable.var_name}"] = result

        return latest_success, values

    @property
    def conditions(self):
        return [
            condition_variable.condition
            for condition_variable in self.condition_variables
        ]


class ReturnValueTest:
    class InvalidExpression(ValueError):
        pass

    COMPARATORS = tuple(_COMPARATOR_FUNCTIONS)

    class ReturnValueTestSchema(CamelCaseSchema):
        SKIP_VALUES = (None,)
        comparator = fields.Str(required=True, validate=OneOf(_COMPARATOR_FUNCTIONS))
        value = fields.Raw(
            allow_none=False, required=True
        )  # any valid type (excludes None)
        index = fields.Int(strict=True, required=False, validate=Range(min=0))

        @post_load
        def make(self, data, **kwargs):
            return ReturnValueTest(**data)

    def __init__(self, comparator: str, value: Any, index: int = None):
        if comparator not in self.COMPARATORS:
            raise self.InvalidExpression(
                f'"{comparator}" is not a permitted comparator.'
            )

        if index is not None and (not isinstance(index, int) or index < 0):
            raise self.InvalidExpression(
                f'"{index}" is not a permitted index. Must be a an non-negative integer.'
            )

        if not is_context_variable(value):
            # adjust stored value to be JSON serializable
            if isinstance(value, (tuple, set)):
                value = list(value)
            if isinstance(value, bytes):
                value = HexBytes(value).hex()

            try:
                json.dumps(value)
            except TypeError:
                raise self.InvalidExpression(
                    f"No JSON serializable equivalent found for type {type(value)}"
                )

            # verify that value is valid, but don't set it here so as not to change the value;
            # it will be sanitized at eval time. Need to maintain serialization/deserialization
            # consistency
            self._sanitize_value(value)

        self.comparator = comparator
        self.value = value
        self.index = index

    @classmethod
    def _sanitize_value(cls, value):
        try:
            return ast.literal_eval(str(value))
        except Exception:
            raise cls.InvalidExpression(f'"{value}" is not a permitted value.')

    @staticmethod
    def __handle_potential_bytes(data: Any) -> Any:
        return HexBytes(data).hex() if isinstance(data, bytes) else data

    def _process_data(self, data: Any, index: Optional[int]) -> Any:
        """
        If an index is specified, return the value at that index in the data if data is list-like.
        Otherwise, return the data.
        """
        processed_data = data

        # try to get indexed entry first
        if index is not None:
            if not isinstance(processed_data, (list, tuple)):
                raise ReturnValueEvaluationError(
                    f"Index: {index} and Value: {processed_data} are not compatible types."
                )
            try:
                processed_data = data[index]
            except IndexError:
                raise ReturnValueEvaluationError(
                    f"Index '{index}' not found in returned data."
                )

        if isinstance(processed_data, (list, tuple)):
            # convert any bytes in list to hex (include nested lists/tuples); no additional indexing
            processed_data = [
                self._process_data(data=item, index=None) for item in processed_data
            ]
            return processed_data

        # convert bytes to hex if necessary
        return self.__handle_potential_bytes(processed_data)

    def eval(self, data) -> bool:
        if is_context_variable(self.value):
            # programming error if we get here
            raise RuntimeError(
                f"Return value comparator contains an unprocessed context variable (value={self.value}) and is not valid "
                f"for condition evaluation."
            )

        processed_data = self._process_data(data, self.index)
        left_operand = self._sanitize_value(processed_data)
        right_operand = self._sanitize_value(self.value)
        result = _COMPARATOR_FUNCTIONS[self.comparator](left_operand, right_operand)
        return result

    def with_resolved_context(self, **context):
        value = _resolve_context_variable(self.value, **context)
        return ReturnValueTest(self.comparator, value=value, index=self.index)


class ConditionLingo(_Serializable):
    VERSION = "1.0.0"

    class Schema(Schema):
        version = fields.Str(required=True)
        condition = _ConditionField(required=True)

        # maintain field declaration ordering
        class Meta:
            ordered = True

        @validates("version")
        def validate_version(self, version):
            ConditionLingo.check_version_compatibility(version)

        @pre_load
        def set_lingo_version(self, data, **kwargs):
            version = data.get("version")
            self.context["lingo_version"] = version
            return data

        @post_load
        def make(self, data, **kwargs):
            return ConditionLingo(**data)

    """
    A Collection of access control conditions evaluated as a compound boolean expression.

    This is an alternate implementation of the condition expression format used in
    the Lit Protocol (https://github.com/LIT-Protocol); credit to the authors for inspiring this work.
    """

    def __init__(self, condition: AccessControlCondition, version: str = VERSION):
        self.condition = condition
        self.check_version_compatibility(version)
        self.version = version
        self.id = md5(bytes(self)).hexdigest()[:6]

    @classmethod
    def from_dict(cls, data: Lingo) -> "ConditionLingo":
        try:
            return super().from_dict(data)
        except ValidationError as e:
            raise InvalidConditionLingo(f"Invalid condition grammar: {e}")

    @classmethod
    def from_json(cls, data: str) -> 'ConditionLingo':
        try:
            return super().from_json(data)
        except ValidationError as e:
            raise InvalidConditionLingo(f"Invalid condition grammar: {e}")

    def to_base64(self) -> bytes:
        data = base64.b64encode(self.to_json().encode())
        return data

    @classmethod
    def from_base64(cls, data: bytes) -> 'ConditionLingo':
        decoded_json = base64.b64decode(data).decode()
        instance = cls.from_json(decoded_json)
        return instance

    def __bytes__(self) -> bytes:
        data = self.to_json().encode()
        return data

    def __repr__(self):
        return f"{self.__class__.__name__} (version={self.version} | id={self.id} | size={len(bytes(self))}) | condition=({self.condition})"

    def eval(self, *args, **kwargs) -> bool:
        result, _ = self.condition.verify(*args, **kwargs)
        return result

    @classmethod
    def resolve_condition_class(
        cls, condition: ConditionDict, version: int = None
    ) -> Type[AccessControlCondition]:
        """
        Inspects a given block of JSON and attempts to resolve it's intended datatype within the
        conditions expression framework.
        """
        from nucypher.policy.conditions.evm import ContractCondition, RPCCondition
        from nucypher.policy.conditions.offchain import JsonApiCondition
        from nucypher.policy.conditions.time import TimeCondition

        # version logical adjustments can be made here as required

        condition_type = condition.get("conditionType")
        for condition in (
            TimeCondition,
            ContractCondition,
            RPCCondition,
            CompoundAccessControlCondition,
            JsonApiCondition,
            SequentialAccessControlCondition,
        ):
            if condition.CONDITION_TYPE == condition_type:
                return condition

        raise InvalidConditionLingo(
            f"Cannot resolve condition lingo, {condition}, with condition type {condition_type}"
        )

    @classmethod
    def check_version_compatibility(cls, version: str):
        if parse_version(version).major > parse_version(cls.VERSION).major:
            raise InvalidConditionLingo(
                f"Version provided, {version}, is incompatible with current version {cls.VERSION}"
            )


class ExecutionCallAccessControlCondition(AccessControlCondition):
    """
    Conditions that utilize underlying ExecutionCall objects.
    """

    class Schema(AccessControlCondition.Schema):
        return_value_test = fields.Nested(
            ReturnValueTest.ReturnValueTestSchema(), required=True
        )

    def __init__(
        self,
        condition_type: str,
        return_value_test: ReturnValueTest,
        name: Optional[str] = None,
        *args,
        **kwargs,
    ):
        self.return_value_test = return_value_test
        try:
            self.execution_call = self._create_execution_call(*args, **kwargs)
        except ValueError as e:
            raise InvalidCondition(str(e))

        super().__init__(condition_type=condition_type, name=name)

    @abstractmethod
    def _create_execution_call(self, *args, **kwargs) -> ExecutionCall:
        """
        Returns the execution call that the condition executes.
        """
        raise NotImplementedError

    def verify(self, *args, **kwargs) -> Tuple[bool, Any]:
        """
        Verifies the condition is met by performing execution call and
        evaluating the return value test.
        """
        result = self.execution_call.execute(*args, **kwargs)

        resolved_return_value_test = self.return_value_test.with_resolved_context(
            **kwargs
        )
        eval_result = resolved_return_value_test.eval(result)  # test
        return eval_result, result
