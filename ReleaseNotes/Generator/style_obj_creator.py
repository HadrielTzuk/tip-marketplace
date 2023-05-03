import docx.enum.text
import docx.shared

import settings
import style_datamodels


def create_header_style() -> style_datamodels.HeaderStyle:
    """Creates and returns a header style object"""
    return style_datamodels.HeaderStyle(
        header_distance=0,
        left_margin=0,
        right_margin=0,
        different_first_page_header_footer=True,
    )


def create_title_style() -> style_datamodels.TitleStyle:
    """Creates and returns a title style object"""
    return style_datamodels.TitleStyle(
        alignment=docx.enum.text.WD_PARAGRAPH_ALIGNMENT.CENTER,
        space_before=docx.shared.Pt(22),
        is_bold=settings.IS_DOCUMENT_TITLE_BOLD,
        is_underline=settings.IS_DOCUMENT_TITLE_UNDERLINED,
        font_name=settings.DOCUMENT_FONT,
        font_size=docx.shared.Pt(settings.DOCUMENT_TITLE_FONT_SIZE),
        text_color=settings.DOCUMENT_TEXT_COLOR,
    )


def create_publish_time_style() -> style_datamodels.PublishDateStyle:
    """Creates and returns a publish-time object"""
    return style_datamodels.PublishDateStyle(
        alignment=docx.enum.text.WD_PARAGRAPH_ALIGNMENT.CENTER,
        space_before=docx.shared.Pt(22),
        is_bold=settings.IS_PUBLISH_DATE_BOLD,
        is_underline=settings.IS_PUBLISH_DATE_UNDERLINED,
        font_name=settings.DOCUMENT_FONT,
        font_size=docx.shared.Pt(settings.PUBLISH_DATE_FONT_SIZE),
        text_color=settings.DOCUMENT_TEXT_COLOR,
    )


def create_tech_details_title_style() -> style_datamodels.TechDetailsTitleStyle:
    """Creates and returns a tech details title object"""
    return style_datamodels.TechDetailsTitleStyle(
        alignment=docx.enum.text.WD_PARAGRAPH_ALIGNMENT.LEFT,
        space_before=docx.shared.Pt(48),
        left_indent=docx.shared.Cm(2.5),
        is_bold=settings.IS_TECH_DETAILS_TITLE_BOLD,
        is_underline=settings.IS_TECH_DETAILS_TITLE_UNDERLINED,
        font_name=settings.DOCUMENT_FONT,
        font_size=docx.shared.Pt(settings.TECH_DETAILS_TITLE_FONT_SIZE),
        text_color=settings.DOCUMENT_TEXT_COLOR,
    )


def create_tech_details_text_style() -> style_datamodels.TechDetailsTextStyle:
    """Creates and returns a tech details text style object"""
    return style_datamodels.TechDetailsTextStyle(
        left_indent=docx.shared.Cm(3.5),
        is_underline=settings.IS_TECH_DETAILS_TEXT_UNDERLINED,
        font_name=settings.DOCUMENT_FONT,
        font_size=docx.shared.Pt(settings.TECH_DETAILS_TEXT_FONT_SIZE),
        text_color=settings.DOCUMENT_TEXT_COLOR,
    )


def create_main_text_title_style() -> style_datamodels.MainTextTitleStyle:
    """Creates and returns a tech details title style object"""
    return style_datamodels.MainTextTitleStyle(
        space_before=docx.shared.Pt(32),
        space_after=docx.shared.Pt(18),
        left_indent=docx.shared.Cm(2.5),
        is_bold=settings.IS_MAIN_BODY_BOLD,
        is_underline=settings.IS_MAIN_BODY_UNDERLINED,
        font_name=settings.DOCUMENT_FONT,
        font_size=docx.shared.Pt(settings.MAIN_BODY_TITLE_FONT_SIZE),
        text_color=settings.DOCUMENT_TEXT_COLOR,
    )


def create_footer_style() -> style_datamodels.FooterStyle:
    """Creates and returns a footer style object"""
    return style_datamodels.FooterStyle(
        alignment=docx.enum.text.WD_PARAGRAPH_ALIGNMENT.RIGHT,
        space_before=docx.shared.Pt(18.5),
        right_indent=docx.shared.Cm(2),
        left_indent=docx.shared.Cm(1),
        table_rows=1,
        table_columns=2,
        logo_width=docx.shared.Cm(3),
        font_name=settings.DOCUMENT_FONT,
        font_size=docx.shared.Pt(9),
    )
