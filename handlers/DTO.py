from dataclasses import dataclass
from bs4 import Tag

@dataclass
class FormUrl:
    url: str
    form: Tag

@dataclass
class FormRequest:
    method: str
    post_url: str
    form: Tag
    post_data: dict[str, str]