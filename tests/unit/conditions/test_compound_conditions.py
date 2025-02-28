from unittest.mock import Mock

import pytest

from nucypher.policy.conditions.base import AccessControlCondition
from nucypher.policy.conditions.lingo import (
    AndCompoundCondition,
    NotCompoundCondition,
    OrCompoundCondition,
)


@pytest.fixture(scope="function")
def mock_conditions():
    condition_1 = Mock(spec=AccessControlCondition)
    condition_1.verify.return_value = (True, 1)
    condition_1.to_dict.return_value = {
        "value": 1
    }  # needed for "id" value calc for CompoundAccessControlCondition

    condition_2 = Mock(spec=AccessControlCondition)
    condition_2.verify.return_value = (True, 2)
    condition_2.to_dict.return_value = {"value": 2}

    condition_3 = Mock(spec=AccessControlCondition)
    condition_3.verify.return_value = (True, 3)
    condition_3.to_dict.return_value = {"value": 3}

    condition_4 = Mock(spec=AccessControlCondition)
    condition_4.verify.return_value = (True, 4)
    condition_4.to_dict.return_value = {"value": 4}

    return condition_1, condition_2, condition_3, condition_4


def test_and_condition_and_short_circuit(mock_conditions):
    condition_1, condition_2, condition_3, condition_4 = mock_conditions

    and_condition = AndCompoundCondition(
        operands=[
            condition_1,
            condition_2,
            condition_3,
            condition_4,
        ]
    )

    # ensure that all conditions evaluated when all return True
    result, value = and_condition.verify()
    assert result is True
    assert len(value) == 4, "all conditions evaluated"
    assert value == [1, 2, 3, 4]

    # ensure that short circuit happens when 1st condition is false
    condition_1.verify.return_value = (False, 1)
    result, value = and_condition.verify()
    assert result is False
    assert len(value) == 1, "only one condition evaluated"
    assert value == [1]

    # short circuit occurs for 3rd entry
    condition_1.verify.return_value = (True, 1)
    condition_3.verify.return_value = (False, 3)
    result, value = and_condition.verify()
    assert result is False
    assert len(value) == 3, "3-of-4 conditions evaluated"
    assert value == [1, 2, 3]


def test_or_condition_and_short_circuit(mock_conditions):
    condition_1, condition_2, condition_3, condition_4 = mock_conditions

    or_condition = OrCompoundCondition(
        operands=[
            condition_1,
            condition_2,
            condition_3,
            condition_4,
        ]
    )

    # ensure that only first condition evaluated when first is True
    condition_1.verify.return_value = (True, 1)  # short circuit here
    result, value = or_condition.verify()
    assert result is True
    assert len(value) == 1, "only first condition needs to be evaluated"
    assert value == [1]

    # ensure first True condition is returned
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (False, 2)
    condition_3.verify.return_value = (True, 3)  # short circuit here

    result, value = or_condition.verify()
    assert result is True
    assert len(value) == 3, "third condition causes short circuit"
    assert value == [1, 2, 3]

    # no short circuit occurs when all are False
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (False, 2)
    condition_3.verify.return_value = (False, 3)
    condition_4.verify.return_value = (False, 4)

    result, value = or_condition.verify()
    assert result is False
    assert len(value) == 4, "all conditions evaluated"
    assert value == [1, 2, 3, 4]


def test_compound_condition(mock_conditions):
    condition_1, condition_2, condition_3, condition_4 = mock_conditions

    compound_condition = AndCompoundCondition(
        operands=[
            OrCompoundCondition(
                operands=[
                    condition_1,
                    condition_2,
                    condition_3,
                ]
            ),
            condition_4,
        ]
    )

    # all conditions are True
    result, value = compound_condition.verify()
    assert result is True
    assert len(value) == 2, "or_condition and condition_4"
    assert value == [[1], 4]

    # or condition is False
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (False, 2)
    condition_3.verify.return_value = (False, 3)
    result, value = compound_condition.verify()
    assert result is False
    assert len(value) == 1, "or_condition"
    assert value == [
        [1, 2, 3]
    ]  # or-condition does not short circuit, but and-condition is short-circuited because or-condition is False

    # or condition is True but condition 4 is False
    condition_1.verify.return_value = (True, 1)
    condition_4.verify.return_value = (False, 4)

    result, value = compound_condition.verify()
    assert result is False
    assert len(value) == 2, "or_condition and condition_4"
    assert value == [
        [1],
        4,
    ]  # or-condition short-circuited because condition_1 was True

    # condition_4 is now true
    condition_4.verify.return_value = (True, 4)
    result, value = compound_condition.verify()
    assert result is True
    assert len(value) == 2, "or_condition and condition_4"
    assert value == [
        [1],
        4,
    ]  # or-condition short-circuited because condition_1 was True


def test_nested_compound_condition(mock_conditions):
    condition_1, condition_2, condition_3, condition_4 = mock_conditions

    nested_compound_condition = AndCompoundCondition(
        operands=[
            OrCompoundCondition(
                operands=[
                    condition_1,
                    AndCompoundCondition(
                        operands=[
                            condition_2,
                            condition_3,
                        ]
                    ),
                ]
            ),
            condition_4,
        ]
    )

    # all conditions are True
    result, value = nested_compound_condition.verify()
    assert result is True
    assert len(value) == 2, "or_condition and condition_4"
    assert value == [[1], 4]  # or short-circuited since condition_1 is True

    # set condition_1 to False so nested and-condition must be evaluated
    condition_1.verify.return_value = (False, 1)

    result, value = nested_compound_condition.verify()
    assert result is True
    assert len(value) == 2, "or_condition and condition_4"
    assert value == [
        [1, [2, 3]],
        4,
    ]  # nested and-condition was evaluated and evaluated to True

    # set condition_4 to False so that overall result flips to False
    condition_4.verify.return_value = (False, 4)
    result, value = nested_compound_condition.verify()
    assert result is False
    assert len(value) == 2, "or_condition and condition_4"
    assert value == [[1, [2, 3]], 4]


def test_not_compound_condition(mock_conditions):
    condition_1, condition_2, condition_3, condition_4 = mock_conditions

    not_condition = NotCompoundCondition(operand=condition_1)

    #
    # simple `not`
    #
    condition_1.verify.return_value = (True, 1)
    result, value = not_condition.verify()
    assert result is False
    assert value == 1

    condition_1.verify.return_value = (False, 2)
    result, value = not_condition.verify()
    assert result is True
    assert value == 2

    #
    # `not` of `or` condition
    #

    # only True
    condition_1.verify.return_value = (True, 1)
    condition_2.verify.return_value = (True, 2)
    condition_3.verify.return_value = (True, 3)

    or_condition = OrCompoundCondition(
        operands=[
            condition_1,
            condition_2,
            condition_3,
        ]
    )
    not_condition = NotCompoundCondition(operand=or_condition)
    or_result, or_value = or_condition.verify()
    result, value = not_condition.verify()
    assert result is False
    assert result is (not or_result)
    assert value == or_value

    # only False
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (False, 2)
    condition_3.verify.return_value = (False, 3)
    or_result, or_value = or_condition.verify()
    result, value = not_condition.verify()
    assert result is True
    assert result is (not or_result)
    assert value == or_value

    # mixture of True/False
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (False, 2)
    condition_3.verify.return_value = (True, 3)
    or_result, or_value = or_condition.verify()
    result, value = not_condition.verify()
    assert result is False
    assert result is (not or_result)
    assert value == or_value

    #
    # `not` of `and` condition
    #

    # only True
    condition_1.verify.return_value = (True, 1)
    condition_2.verify.return_value = (True, 2)
    condition_3.verify.return_value = (True, 3)

    and_condition = AndCompoundCondition(
        operands=[
            condition_1,
            condition_2,
            condition_3,
        ]
    )
    not_condition = NotCompoundCondition(operand=and_condition)

    and_result, and_value = and_condition.verify()
    result, value = not_condition.verify()
    assert result is False
    assert result is (not and_result)
    assert value == and_value

    # only False
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (False, 2)
    condition_3.verify.return_value = (False, 3)
    and_result, and_value = and_condition.verify()
    result, value = not_condition.verify()
    assert result is True
    assert result is (not and_result)
    assert value == and_value

    # mixture of True/False
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (True, 2)
    condition_3.verify.return_value = (False, 3)
    and_result, and_value = and_condition.verify()
    result, value = not_condition.verify()
    assert result is True
    assert result is (not and_result)
    assert value == and_value

    #
    # Complex nested `or` and `and` (reused nested compound condition in previous test)
    #
    nested_compound_condition = AndCompoundCondition(
        operands=[
            OrCompoundCondition(
                operands=[
                    condition_1,
                    AndCompoundCondition(
                        operands=[
                            condition_2,
                            condition_3,
                        ]
                    ),
                ]
            ),
            condition_4,
        ]
    )

    not_condition = NotCompoundCondition(operand=nested_compound_condition)

    # reset all conditions to True
    condition_1.verify.return_value = (True, 1)
    condition_2.verify.return_value = (True, 2)
    condition_3.verify.return_value = (True, 3)
    condition_4.verify.return_value = (True, 4)

    nested_result, nested_value = nested_compound_condition.verify()
    result, value = not_condition.verify()
    assert result is False
    assert result is (not nested_result)
    assert value == nested_value

    # set condition_1 to False so nested and-condition must be evaluated
    condition_1.verify.return_value = (False, 1)

    nested_result, nested_value = nested_compound_condition.verify()
    result, value = not_condition.verify()
    assert result is False
    assert result is (not nested_result)
    assert value == nested_value

    # set condition_4 to False so that overall result flips to False, so `not` is now True
    condition_4.verify.return_value = (False, 4)
    nested_result, nested_value = nested_compound_condition.verify()
    result, value = not_condition.verify()
    assert result is True
    assert result is (not nested_result)
    assert value == nested_value
