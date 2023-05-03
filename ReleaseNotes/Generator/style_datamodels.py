from dataclasses import dataclass

import docx.shared
from docx.enum import text


@dataclass
class HeaderStyle:
    """Data class for header styling configuration"""
    header_distance: int
    left_margin: int
    right_margin: int
    different_first_page_header_footer: bool


@dataclass
class TitleStyle:
    """Data class for title styling configuration"""
    alignment: text.WD_PARAGRAPH_ALIGNMENT
    space_before: docx.shared.Pt
    is_bold: bool
    is_underline: bool
    font_name: str
    font_size: docx.shared.Pt
    text_color: docx.shared.RGBColor


@dataclass
class PublishDateStyle:
    """Data class for publish time styling configuration"""
    alignment: text.WD_PARAGRAPH_ALIGNMENT
    space_before: docx.shared.Pt
    is_bold: bool
    is_underline: bool
    font_name: str
    font_size: docx.shared.Pt
    text_color: docx.shared.RGBColor


@dataclass
class TechDetailsTitleStyle:
    """Data class for tech details title styling configuration"""
    alignment: text.WD_PARAGRAPH_ALIGNMENT
    space_before: docx.shared.Pt
    left_indent: docx.shared.Cm
    is_bold: bool
    is_underline: bool
    font_name: str
    font_size: docx.shared.Pt
    text_color: docx.shared.RGBColor


@dataclass
class TechDetailsTextStyle:
    """Data class for tech details text styling configuration"""
    left_indent: docx.shared.Cm
    is_underline: bool
    font_name: str
    font_size: docx.shared.Pt
    text_color: docx.shared.RGBColor


@dataclass
class MainTextTitleStyle:
    """Data class for main text title styling configuration"""
    space_before: docx.shared.Pt
    space_after: docx.shared.Pt
    left_indent: docx.shared.Cm
    is_bold: bool
    is_underline: bool
    font_name: str
    font_size: docx.shared.Pt
    text_color: docx.shared.RGBColor


@dataclass
class FooterStyle:
    """Data class for footer styling configuration"""
    alignment: text.WD_PARAGRAPH_ALIGNMENT
    space_before: docx.shared.Pt
    right_indent: docx.shared.Cm
    left_indent: docx.shared.Cm
    table_rows: int
    table_columns: int
    logo_width: docx.shared.Cm
    font_name: str
    font_size: docx.shared.Pt
