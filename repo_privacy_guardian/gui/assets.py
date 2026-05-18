"""GUI asset loading, theming, and refresh helpers."""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DARK_ICON_COLOR = "#E7F4F0"
ICON_SIZE = (24, 24)


def load_pillow_icon_modules() -> tuple[object, object]:
    from PIL import Image, ImageColor

    return Image, ImageColor


def load_pillow_theme_modules() -> tuple[object, object]:
    from PIL import Image, ImageTk

    return Image, ImageTk


def tint_gui_icon(image: Any, color: tuple[int, int, int]) -> Any:
    try:
        from PIL import Image, ImageChops
    except Exception:
        return image

    source = image.convert("RGBA")
    luminance = source.convert("L")
    darkness_mask = Image.eval(luminance, lambda pixel: 255 - pixel)
    alpha_mask = ImageChops.multiply(darkness_mask, source.getchannel("A"))
    tinted = Image.new("RGBA", image.size, color + (0,))
    tinted.putalpha(alpha_mask)
    return tinted


def theme_token_name_for_color(
    attrs: Mapping[str, object],
    color: str,
    *,
    parse_hex_rgb: Callable[[str], tuple[int, int, int] | None],
) -> str | None:
    matches = [
        name
        for name, value in attrs.items()
        if name.startswith("_") and isinstance(value, str) and value == color and parse_hex_rgb(value) is not None
    ]
    if len(matches) == 1:
        return matches[0]
    preferred = (
        "_header_fg",
        "_surface_fg",
        "_surface_alt",
        "_white_panel_fg",
        "_info_panel_fg",
        "_success_panel_fg",
        "_warning_panel_fg",
        "_page_bg",
    )
    for name in preferred:
        if name in matches:
            return name
    return matches[0] if matches else None


@dataclass
class GuiAssetManager:
    tk: object
    ctk: object
    root: object
    asset_filenames: Callable[[], Iterable[str]]
    themeable_asset_filenames: Callable[[], Collection[str]]
    asset_path: Callable[[str], Path | None]
    parse_hex_rgb: Callable[[str], tuple[int, int, int] | None]
    blend_themeable_asset_background: Callable[[object, tuple[int, int, int]], object]
    effective_appearance: Callable[[], str]
    dark_appearance: Callable[[], str]
    theme_attrs: Callable[[], Mapping[str, object]]
    record_warning: Callable[[str, Exception | None], None]
    asset_images: dict[str, object] = field(default_factory=dict)
    themed_asset_images: dict[tuple[str, str, str], object] = field(default_factory=dict)
    button_asset_images: dict[str, object] = field(default_factory=dict)
    asset_labels: list[dict[str, object]] = field(default_factory=list)

    def load_asset_images(self) -> dict[str, object]:
        images: dict[str, object] = {}
        for filename in self.asset_filenames():
            asset_path = self.asset_path(filename)
            if asset_path is None:
                continue
            try:
                images[filename] = self.tk.PhotoImage(file=str(asset_path))  # type: ignore[attr-defined]
            except Exception:
                continue
        self.asset_images = images
        return images

    def load_button_asset_images(self) -> dict[str, object]:
        ctk_image = getattr(self.ctk, "CTkImage", None)
        if ctk_image is None:
            self.button_asset_images = {}
            return {}

        try:
            image_module, image_color_module = load_pillow_icon_modules()
        except Exception:
            self.button_asset_images = {}
            return {}

        images: dict[str, object] = {}
        for filename in self.asset_filenames():
            if not filename.startswith("icon-"):
                continue
            asset_path = self.asset_path(filename)
            if asset_path is None:
                continue
            try:
                with image_module.open(asset_path) as source:  # type: ignore[attr-defined]
                    image = source.convert("RGBA").copy()
                dark_icon_rgb = image_color_module.getrgb(DARK_ICON_COLOR)[:3]  # type: ignore[attr-defined]
                dark_image = tint_gui_icon(image, dark_icon_rgb)
                images[filename] = ctk_image(light_image=image, dark_image=dark_image, size=ICON_SIZE)
            except Exception:
                continue
        self.button_asset_images = images
        return images

    def image(self, filename: str, *, background: str | None = None) -> object | None:
        effective_appearance = self.effective_appearance()
        if (
            background
            and effective_appearance == self.dark_appearance()
            and filename in self.themeable_asset_filenames()
        ):
            cache_key = (filename, effective_appearance, background)
            cached_image = self.themed_asset_images.get(cache_key)
            if cached_image is not None:
                return cached_image
            background_rgb = self.parse_hex_rgb(background)
            asset_path = self.asset_path(filename)
            if background_rgb is not None and asset_path is not None:
                try:
                    image_module, image_tk_module = load_pillow_theme_modules()

                    with image_module.open(asset_path) as source:  # type: ignore[attr-defined]
                        themed_source = self.blend_themeable_asset_background(source, background_rgb)
                    themed_image = image_tk_module.PhotoImage(themed_source)  # type: ignore[attr-defined]
                    self.themed_asset_images[cache_key] = themed_image
                    return themed_image
                except Exception:
                    pass
        return self.asset_images.get(filename)

    def set_window_icon(self) -> None:
        icon = self.image("app-icon.png")
        if icon is None:
            return
        try:
            self.root.iconphoto(True, icon)  # type: ignore[attr-defined]
        except Exception:
            pass

    def theme_token_name_for_color(self, color: str) -> str | None:
        return theme_token_name_for_color(
            self.theme_attrs(),
            color,
            parse_hex_rgb=self.parse_hex_rgb,
        )

    def make_label(
        self,
        parent: object,
        filename: str,
        *,
        background: str,
    ) -> object | None:
        image = self.image(filename, background=background)
        if image is None:
            return None
        label = self.tk.Label(  # type: ignore[attr-defined]
            parent,
            image=image,
            background=background,
            borderwidth=0,
            highlightthickness=0,
            padx=0,
            pady=0,
        )
        self.asset_labels.append(
            {
                "label": label,
                "filename": filename,
                "background_token": self.theme_token_name_for_color(background),
            }
        )
        return label

    def button_options(self, filename: str) -> dict[str, object]:
        image = self.button_asset_images.get(filename)
        if image is None:
            return {}
        return {"image": image, "compound": "left"}

    def configure_label_image(self, label: object, filename: str, background: str) -> None:
        image = self.image(filename, background=background)
        if image is None:
            return
        try:
            label.configure(image=image, background=background)  # type: ignore[attr-defined]
        except Exception as exc:
            self.record_warning("asset label image update failed", exc)

    def refresh_labels(self) -> None:
        self.themed_asset_images.clear()
        attrs = self.theme_attrs()
        for item in list(self.asset_labels):
            label = item.get("label")
            filename = item.get("filename")
            background_token = item.get("background_token")
            if label is None or not isinstance(filename, str):
                continue
            background = None
            if isinstance(background_token, str):
                background = attrs.get(background_token)
            if not isinstance(background, str):
                try:
                    background = label.cget("background")  # type: ignore[attr-defined]
                except Exception:
                    background = None
            if isinstance(background, str):
                self.configure_label_image(label, filename, background)
        self.set_window_icon()
