import re
from http import HTTPStatus
from typing import Dict, NamedTuple, Optional, Tuple

from marshmallow import Schema, post_dump
from web3.providers import BaseProvider

from nucypher.policy.conditions.exceptions import (
    ConditionEvaluationFailed,
    ContextVariableVerificationFailed,
    InvalidCondition,
    InvalidConditionLingo,
    InvalidContextVariableData,
    NoConnectionToChain,
    RequiredContextVariable,
    ReturnValueEvaluationError,
)
from nucypher.policy.conditions.types import ContextDict, Lingo
from nucypher.utilities.logging import Logger

__LOGGER = Logger("condition-eval")


class EvalError(NamedTuple):
    message: str
    status_code: int


def to_camelcase(s):
    parts = iter(s.split("_"))
    return next(parts) + "".join(i.title() for i in parts)


def camel_case_to_snake(data: str) -> str:
    data = re.sub(r"(?<!^)(?=[A-Z])", "_", data).lower()
    return data


class CamelCaseSchema(Schema):
    """Schema that uses camel-case for its external representation
    and snake-case for its internal representation.
    """

    SKIP_VALUES: Tuple = tuple()

    def on_bind_field(self, field_name, field_obj):
        field_obj.data_key = to_camelcase(field_obj.data_key or field_name)

    @post_dump
    def remove_skip_values(self, data, **kwargs):
        return {
            key: value for key, value in data.items() if value not in self.SKIP_VALUES
        }


def validate_condition_lingo(lingo: Lingo) -> None:
    # TODO potentially remove
    from nucypher.policy.conditions.lingo import ConditionLingo

    ConditionLingo.validate_condition_lingo(lingo=lingo)


def evaluate_condition_lingo(
    condition_lingo: Lingo,
    providers: Optional[Dict[int, BaseProvider]] = None,
    context: Optional[ContextDict] = None,
    log: Logger = __LOGGER,
) -> Optional[EvalError]:
    """
    Evaluates condition lingo with the give providers and user supplied context.
    If all conditions are satisfied this function returns None.

    # TODO: Evaluate all conditions even if one fails and report the result
    """

    # prevent circular import
    from nucypher.policy.conditions.lingo import ConditionLingo

    # Setup (don't use mutable defaults)
    context = context or dict()
    providers = providers or dict()
    error = None

    # Evaluate
    try:
        if condition_lingo:
            log.info(f"Evaluating access conditions {condition_lingo}")
            lingo = ConditionLingo.from_dict(condition_lingo)
            result = lingo.eval(providers=providers, **context)
            if not result:
                # explicit condition failure
                error = EvalError(
                    "Decryption conditions not satisfied", HTTPStatus.FORBIDDEN
                )
    except ReturnValueEvaluationError as e:
        error = EvalError(
            f"Unable to evaluate return value: {e}",
            HTTPStatus.BAD_REQUEST,
        )
    except InvalidConditionLingo as e:
        error = EvalError(
            f"Invalid condition grammar: {e}",
            HTTPStatus.BAD_REQUEST,
        )
    except InvalidCondition as e:
        error = EvalError(
            f"Incorrect value provided for condition: {e}",
            HTTPStatus.BAD_REQUEST,
        )
    except RequiredContextVariable as e:
        # TODO: be more specific and name the missing inputs, etc
        error = EvalError(f"Missing required inputs: {e}", HTTPStatus.BAD_REQUEST)
    except InvalidContextVariableData as e:
        error = EvalError(
            f"Invalid data provided for context variable: {e}",
            HTTPStatus.BAD_REQUEST,
        )
    except ContextVariableVerificationFailed as e:
        error = EvalError(
            f"Context variable data could not be verified: {e}",
            HTTPStatus.FORBIDDEN,
        )
    except NoConnectionToChain as e:
        error = EvalError(
            f"Node does not have a connection to chain ID {e.chain}",
            HTTPStatus.NOT_IMPLEMENTED,
        )
    except ConditionEvaluationFailed as e:
        error = EvalError(
            f"Decryption condition not evaluated: {e}", HTTPStatus.BAD_REQUEST
        )
    except Exception as e:
        # TODO: Unsure why we ended up here
        message = (
            f"Unexpected exception while evaluating "
            f"decryption condition ({e.__class__.__name__}): {e}"
        )
        error = EvalError(message, HTTPStatus.INTERNAL_SERVER_ERROR)
        log.warn(message)

    if error:
        error = EvalError(*error)
        log.info(error.message)  # log error message

    return error
