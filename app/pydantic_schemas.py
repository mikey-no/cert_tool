import pathlib
from typing import List, Optional

from pydantic import BaseModel


class CSRPydanticModel(BaseModel):
    common_name: str
    prefix: str
    csr: str
    san: Optional[List[str]]


class RootCertInfoModel(BaseModel):
    root_cert_subject: str
    root_cert_issuer: str
    root_cert_not_valid_before: str
    root_cert_not_valid_after: str
    root_cert_serial_number: str
    root_cert_extensions: str


class CAInfoModel(BaseModel):
    common_name: str
    prefix: str
    location: pathlib.Path
