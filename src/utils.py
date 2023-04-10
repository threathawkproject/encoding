from models import SRO, SDO, SDOType, IndicatorDTO, IndicatorType, MalwareDTO, AttackPatternDTO, LocationDTO 
from stix2 import HashConstant
from stix2 import Relationship, Indicator, Malware, AttackPattern, Location 
from stix2 import ObjectPath, ObservationExpression, EqualityComparisonExpression

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
    return indicator.serialize()

def make_malware(malware_data: MalwareDTO):
    malware = Malware(
        name=malware_data.value,
        is_family=malware_data.is_family
    )
    return malware.serialize() 

def make_attack_pattern(attack_data: AttackPatternDTO):
    ttp = AttackPattern(
        name=attack_data.name,
        description=attack_data.description,
        external_references=attack_data.external_references,
    )

    return ttp.serialize() 


def make_location(location_data: LocationDTO):
    location = Location(
        name=location_data.name,
        country=location_data.country,
        latitude=location_data.latitude,
        longitude=location_data.longitude
    )
    return location.serialize() 



def generate_sdo(sdo: SDO):
    type = sdo.type
    if type == "indicator":
        print(f"Making an indicator with the given data {sdo.data}")
        return make_indicator(sdo.data)
    if type == "malware":
        print(f"Making an malware with the given data {sdo.data}")
        return make_indicator(sdo.data)
    if type == "attack-pattern":
        return make_attack_pattern(sdo.data)
    if type == "location":
        return make_location(sdo.data)
        

def generate_sro(sro: SRO):
    relationship = Relationship(
        source_ref=sro.source,
        target_ref=sro.target,
        relationship_type=sro.rel_type
    )
    return relationship.serialize()