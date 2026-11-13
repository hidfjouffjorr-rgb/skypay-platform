// ======================================
// APP IMAGE UPLOAD
// ======================================

app.post(
  "/api/admin/app-image",
  adminAuth,
  upload.single("image"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: "অ্যাপের ছবি নির্বাচন করুন।"
        });
      }

      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          {
            folder: "skypay/apps",
            resource_type: "image"
          },
          (error, uploadedImage) => {
            if (error) return reject(error);
            resolve(uploadedImage);
          }
        );

        stream.end(req.file.buffer);
      });

      res.status(201).json({
        success: true,
        url: result.secure_url,
        public_id: result.public_id
      });

    } catch (error) {
      console.error("App image upload error:", error);

      res.status(500).json({
        error: "অ্যাপের ছবি আপলোড করা যায়নি।"
      });
    }
  }
);
