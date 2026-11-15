"""Content-type routes of the unscreened media modules (review finding 9)."""

from __future__ import annotations

from forensic_analyze import media


def _fp(fmt: str, *streams: tuple[str, int]) -> dict:
    return {
        "format": {"format_name": fmt},
        "streams": [
            {"index": i, "codec_type": kind, "disposition": {"attached_pic": pic}}
            for i, (kind, pic) in enumerate(streams)
        ],
    }


def test_av_route_names_each_case():
    assert media.av_route(_fp("mp3", ("audio", 0))) == ("", "")
    route, why = media.av_route(_fp("mp3", ("audio", 0), ("video", 1)))
    assert route == "embedded" and "1 embedded picture(s) (cover art, mp3)" in why
    route, why = media.av_route(_fp("mov,mp4,m4a", ("audio", 0), ("video", 0)))
    assert route == "video" and "1 picture or video stream(s)" in why
    assert media.av_route(_fp("yuv4mpegpipe", ("video", 0)))[0] == "video"
    assert media.av_route(_fp("psd_pipe", ("video", 0)))[0] == "image"
    assert media.av_route(_fp("image2", ("video", 0)))[0] == "image"
    # A moving stream beside cover art is a video: every frame is screened.
    assert media.av_route(_fp("mp4", ("video", 1), ("video", 0)))[0] == "video"
    assert media.av_route(None)[0] == "unknown"


def _item(route: str, reason: str) -> media.MediaItem:
    item = media.MediaItem({"volume_index": 0, "inode": "1-128-1", "path": "/a.mp3"})
    item.route, item.route_reason = route, reason
    return item


def test_screen_extra_labels_embedded_pictures_apart_from_mismatches():
    mod = media.MediaModule()
    cover = _item("embedded", "ffprobe found 1 embedded picture(s) (cover art, mp3)")
    cover.screen = media.ScreenResult("/x", "0" * 64, "cleared")
    assert mod.screen_extra(cover).startswith("embedded picture screened: ffprobe found 1")
    cover.screen = media.ScreenResult("/x", "0" * 64, "error", error="ffmpeg failed")
    assert mod.screen_extra(cover).startswith("embedded picture: ffprobe found 1")
    clip = _item("video", "ffprobe found 1 picture or video stream(s) (mp4)")
    assert mod.screen_extra(clip).startswith("content type mismatch: ffprobe found 1")
    assert "screened as video" in mod.screen_extra(clip)
