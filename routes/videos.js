/**
 * DELETE /videos/:id
 * Removes a video record and its storage files.
 */
router.delete('/:id', async (req, res) => {
  const { id } = req.params;

  // 1) Get the record first
  const { data: video, error: fetchError } = await supabase
    .from('videos')
    .select('*')
    .eq('id', id)
    .single();

  if (fetchError) {
    return res.status(500).json({ error: fetchError.message });
  }
  if (!video) {
    return res.status(404).json({ error: 'Video not found' });
  }

  // 2) Remove DB row
  const { error: deleteError } = await supabase
    .from('videos')
    .delete()
    .eq('id', id);

  if (deleteError) {
    return res.status(500).json({ error: deleteError.message });
  }

  // 3) Delete storage files
  try {
    if (video.video_url) {
      const videoPath = video.video_url.split('/videos/')[1];
      if (videoPath) {
        await supabase.storage.from('videos').remove([videoPath]);
      }
    }

    if (video.thumbnail_url) {
      const thumbPath = video.thumbnail_url.split('/thumbnails/')[1];
      if (thumbPath) {
        await supabase.storage.from('thumbnails').remove([thumbPath]);
      }
    }
  } catch (storageError) {
    console.error('Storage delete error:', storageError);
    // Not critical enough to block response
  }

  return res.json({ success: true, deletedId: id });
});
