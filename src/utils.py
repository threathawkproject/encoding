from models import SDO, IndicatorDTO, IndicatorType
from stix2 import HashConstant
from stix2 import Indicator, ObjectPath, ObservationExpression, EqualityComparisonExpression

def make_indicator(indicator_data: IndicatorDTO):
    ioc = indicator_data.value
    indicator_type = indicator_data.type
    pattern = None
    if indicator_type is IndicatorType.IPv4:
        expression = EqualityComparisonExpression(
            ObjectPath("ipv4-addr", ["value"]),
            ioc
        )
        pattern = ObservationExpression(expression)
    elif indicator_type is IndicatorType.IPv6:
        expression = EqualityComparisonExpression(
            ObjectPath("ipv6-addr", ["value"]),
            ioc
        )
        pattern = ObservationExpression(expression)
    elif (indicator_type is not IndicatorType.Email) and (indicator_type is not IndicatorType.URL):
        expression = EqualityComparisonExpression(
            ObjectPath("file", ["hashes", str(indicator_type)]),
            HashConstant(ioc, str(indicator_type))
        )
        pattern = ObservationExpression(expression)
    else:
        expression = EqualityComparisonExpression(
            ObjectPath(str(indicator_type).lower(), ["value"]),
            ioc
        )
        pattern = ObservationExpression(expression)

    indicator = Indicator(
        name=ioc,
        pattern_type="stix",
        pattern=pattern
    )
    return indicator

def convert(sdo: SDO):
    indicator_type = sdo.type
    if indicator_type == "indicator":
        print(f"Making an indicator with the given data {sdo.data}")
        return make_indicator(sdo.data)