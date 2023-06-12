from models import SCO, SRO, SDO, SDOType, IndicatorDTO, IndicatorType, MalwareDTO, AttackPatternDTO, LocationDTO, DomainNameDTO
from stix2 import HashConstant
from stix2 import Relationship, Indicator, Malware, AttackPattern, Location, DomainName
from stix2 import ObjectPath, ObservationExpression, EqualityComparisonExpression

import json

def make_json(stix_obj_json_str):
    print("Serializing..")
    return json.loads(stix_obj_json_str)

def make_indicator(indicator_data: IndicatorDTO):
    ioc = indicator_data.value
    indicator_type = indicator_data.type
    pattern = None
    if indicator_type is IndicatorType.IP:
        expression = EqualityComparisonExpression(
            ObjectPath("ip-addr", ["value"]),
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
        pattern=pattern,
        node_type=indicator_type.value,
        extensions={
            "extension-definition--dd73de4f-a7f3-49ea-8ec1-8e884196b7a8": {
                'extension_type': 'toplevel-property-extension',
            },
        }
    )
    indicator_json_str = indicator.serialize()
    return make_json(indicator_json_str)


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

    ttp_json_str = ttp.serialize()

    return make_json(ttp_json_str)



def make_location(location_data: LocationDTO):
    location = Location(
        name=location_data.name,
        country=location_data.country,
        latitude=location_data.latitude,
        longitude=location_data.longitude
    )
    location_json_str = location.serialize()
    return make_json(location_json_str)


def make_domain_name(domain_name_data: DomainNameDTO):
    domain_name = DomainName(
        name=domain_name_data.name,
        value=domain_name_data.name,
        extensions={
            "extension-definition--dd73de4f-a7f3-49ea-8ec1-8e884196b7a8": {
                'extension_type': 'toplevel-property-extension',
            },
        }
    )
    domain_name_json_str = domain_name.serialize()
    return make_json(domain_name_json_str)


def generate_sdo(sdo: SDO):
    type = sdo.type
    if type == "indicator":
        print(f"Making an indicator with the given data {sdo.data}")
        return make_indicator(sdo.data)
    if type == "malware":
        print(f"Making an malware with the given data {sdo.data}")
        return make_indicator(sdo.data)
    if type == "attack-pattern":
        return make_attack_pattern(sdo.da.ta)
    if type == "location":
        return make_location(sdo.data)


def generate_sco(sco: SCO):
    type = sco.type
    if type == "domain-name":
        domain_name_dto = sco.data
        return make_domain_name(domain_name_dto)


def generate_sro(sro: SRO):
    relationship = Relationship(
        source_ref=sro.source,
        target_ref=sro.target,
        relationship_type=sro.rel_type
    )
    return relationship.serialize()
