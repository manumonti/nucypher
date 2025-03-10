import os
import random

import pytest

from nucypher.policy.conditions.exceptions import ReturnValueEvaluationError
from nucypher.policy.conditions.lingo import ReturnValueTest


def test_return_value_test_schema():
    schema = ReturnValueTest.ReturnValueTestSchema()
    return_value_test = ReturnValueTest(comparator=">", value=0, index=1)

    test_dict = schema.dump(return_value_test)

    # no issues here
    errors = schema.validate(data=test_dict)
    assert not errors, f"{errors}"

    # missing comparator should cause error
    test_dict = schema.dump(return_value_test)
    del test_dict["comparator"]
    errors = schema.validate(data=test_dict)
    assert errors, f"{errors}"

    # missing value should cause error
    test_dict = schema.dump(return_value_test)
    del test_dict["value"]
    errors = schema.validate(data=test_dict)
    assert errors, f"{errors}"

    # missing index should NOT cause any error since optional
    test_dict = schema.dump(return_value_test)
    del test_dict["index"]
    errors = schema.validate(data=test_dict)
    assert not errors, f"{errors}"


def test_return_value_index():
    with pytest.raises(ReturnValueTest.InvalidExpression):
        _ = ReturnValueTest(comparator=">", value="0", index="james")


def test_return_value_index():
    test = ReturnValueTest(comparator=">", value="0", index=0)
    assert test.eval([1])
    assert not test.eval([-1])

    test = ReturnValueTest(comparator="==", value='"james"', index=3)
    assert test.eval([0, 1, 2, '"james"'])

    with pytest.raises(ReturnValueEvaluationError):
        test.eval([0, 1, 2])


def test_return_value_index_tuple():
    test = ReturnValueTest(comparator=">", value="0", index=0)
    assert test.eval((1,))
    assert not test.eval((-1,))


def test_return_value_test_invalid_comparators():
    with pytest.raises(ReturnValueTest.InvalidExpression):
        _ = ReturnValueTest(comparator="eq", value=1)

    with pytest.raises(ReturnValueTest.InvalidExpression):
        _ = ReturnValueTest(comparator="=", value=1)

    with pytest.raises(ReturnValueTest.InvalidExpression):
        _ = ReturnValueTest(comparator="+", value=1)

    with pytest.raises(ReturnValueTest.InvalidExpression):
        _ = ReturnValueTest(comparator="*", value=1)

    with pytest.raises(ReturnValueTest.InvalidExpression):
        _ = ReturnValueTest(comparator="/", value=1)

    with pytest.raises(ReturnValueTest.InvalidExpression):
        _test = ReturnValueTest(comparator="DROP", value=1)


def test_eval_is_evil():
    # TODO look into more malicious fuzzing cases
    file = f"file_{os.urandom(10).hex()}"
    assert not os.path.isfile(file)
    with pytest.raises(ReturnValueTest.InvalidExpression):
        _test = ReturnValueTest(
            comparator=">",
            value=f"(lambda: (42, __import__('os').system('touch {file}'))[0])()",
        )
    assert not os.path.isfile(file)


def test_return_value_test_with_context_variable_cant_run_eval():
    # known context variable
    test = ReturnValueTest(comparator="==", value=":userAddress")
    with pytest.raises(RuntimeError):
        test.eval("0xaDD9D957170dF6F33982001E4c22eCCdd5539118")

    # fake context variable
    test = ReturnValueTest(comparator="==", value=":fakeContextVar")
    with pytest.raises(RuntimeError):
        test.eval(0)


def test_return_value_test_integer():
    # >
    test = ReturnValueTest(comparator='>', value='0')
    assert test.eval('1')
    assert not test.eval('-1')
    # mixing types can work
    assert test.eval(1)
    assert not test.eval(-1)

    test = ReturnValueTest(comparator='>', value=0)
    assert test.eval(1)
    assert not test.eval(0)
    assert not test.eval(-1)
    # mixed types
    assert test.eval("1")
    assert not test.eval("0")

    # >=
    test = ReturnValueTest(comparator=">=", value=1)
    assert test.eval(2)
    assert test.eval(1)
    assert not test.eval(-2)

    # <
    test = ReturnValueTest(comparator="<", value=2)
    assert not test.eval(3)
    assert not test.eval(2)
    assert test.eval(-3)

    # <=
    test = ReturnValueTest(comparator="<=", value=-1)
    assert not test.eval(3)
    assert test.eval(-1)
    assert test.eval(-3)

    # ==
    test = ReturnValueTest(comparator="==", value=4)
    assert not test.eval(1)
    assert test.eval(4)
    assert not test.eval(-2)

    # !=
    test = ReturnValueTest(comparator="!=", value=20)
    assert test.eval(1)
    assert not test.eval(20)
    assert test.eval(-2)


def test_return_value_test_string():
    # string values must be quoted
    with pytest.raises(ReturnValueTest.InvalidExpression):
        _test = ReturnValueTest(comparator="==", value="foo")

    test = ReturnValueTest(comparator='==', value='"foo"')
    assert test.eval('"foo"')
    assert not test.eval('"bar"')

    test = ReturnValueTest(comparator="!=", value='"foo"')
    assert not test.eval('"foo"')
    assert test.eval('"bar"')

    # mixing types works because the value is evaluated as an int, not a string
    test = ReturnValueTest(
        comparator="==", value="0xaDD9D957170dF6F33982001E4c22eCCdd5539118"
    )
    assert test.eval(992513598061863249514433594012370110655092723992)
    assert test.eval("0xaDD9D957170dF6F33982001E4c22eCCdd5539118")
    assert not test.eval("0xdeadbeef")

    test = ReturnValueTest(
        comparator="!=", value="0xaDD9D957170dF6F33982001E4c22eCCdd5539118"
    )
    assert not test.eval("0xaDD9D957170dF6F33982001E4c22eCCdd5539118")
    assert test.eval("0xdeadbeef")


def test_return_value_test_bool():
    test = ReturnValueTest(comparator="==", value=True)
    assert test.eval(True)
    assert not test.eval(False)
    assert test.eval("True")
    assert not test.eval("False")

    test = ReturnValueTest(comparator="!=", value=False)
    assert test.eval(True)
    assert not test.eval(False)
    assert test.eval("True")
    assert not test.eval("False")

    test = ReturnValueTest(comparator="==", value="True")
    assert test.eval(True)
    assert not test.eval(False)
    assert test.eval("True")
    assert not test.eval("False")

    test = ReturnValueTest(comparator="!=", value="False")
    assert test.eval(True)
    assert not test.eval(False)
    assert test.eval("True")
    assert not test.eval("False")


@pytest.mark.parametrize(
    "test_value",
    [
        '"foo"',  # string
        ":userAddress",  # context variable is an exception case for a string value
        "0xaDD9D957170dF6F33982001E4c22eCCdd5539118",  # string that is evaluated as int
        125,  # int
        1.223,  # float
        b"\xe4\xe4u\x18\x03\x81i\xb74\x0e\xf5\xeb\x18\xf0\x0f\x82",  # bytes
        True,  # bool
        "True",  # bool as string
        (1, True, "love"),  # tuple
        ["a", "b", "c"],  # list
        {"name": "John", "age": 22},  # dict
        {True, False},  # set
    ],
)
def test_return_value_serialization(test_value):
    schema = ReturnValueTest.ReturnValueTestSchema()
    comparator = random.choice(ReturnValueTest.COMPARATORS)
    test = ReturnValueTest(comparator=comparator, value=test_value)
    reloaded = schema.load(schema.dump(test))
    assert (test.comparator == reloaded.comparator) and (
        test.value == reloaded.value
    ), f"test for '{comparator} {test_value}'"
