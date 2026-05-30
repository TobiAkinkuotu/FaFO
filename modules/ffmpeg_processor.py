import ffmpeg
from pathlib import Path

def probe_video(file_path: Path) -> dict:
    """Extract technical metadata from a video using ffprobe."""
    try:
        probe = ffmpeg.probe(str(file_path))
        video_stream = next((stream for stream in probe['streams'] if stream['codec_type'] == 'video'), None)
        
        if not video_stream:
            return {"error": "No video stream found"}
            
        return {
            "duration": float(probe['format'].get('duration', 0)),
            "codec": video_stream.get('codec_name', 'unknown'),
            "resolution": f"{video_stream.get('width', 0)}x{video_stream.get('height', 0)}",
            "frame_rate": eval(video_stream.get('avg_frame_rate', '0/1')),
            "bitrate": int(probe['format'].get('bit_rate', 0))
        }
    except ffmpeg.Error as e:
        return {"error": e.stderr.decode() if e.stderr else str(e)}

def extract_thumbnail(video_path: Path, output_path: Path, time_offset: float = 1.0):
    """Generate a thumbnail from a video at a specific time."""
    try:
        (
            ffmpeg
            .input(str(video_path), ss=time_offset)
            .filter('scale', 320, -1)
            .output(str(output_path), vframes=1)
            .overwrite_output()
            .run(capture_stdout=True, capture_stderr=True)
        )
        return True
    except ffmpeg.Error:
        return False

def extract_frames_for_ocr(video_path: Path, temp_dir: Path, fps: int = 1):
    """Extract frames at given fps interval for OCR processing."""
    output_pattern = str(temp_dir / "frame_%04d.png")
    try:
        (
            ffmpeg
            .input(str(video_path))
            .filter('fps', fps=fps)
            .output(output_pattern)
            .overwrite_output()
            .run(capture_stdout=True, capture_stderr=True)
        )
        # Return list of generated frame paths
        return sorted(list(temp_dir.glob("frame_*.png")))
    except ffmpeg.Error:
        return []
