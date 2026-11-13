// ======================================
// CLOUDINARY IMAGE UPLOAD
// ======================================

app.post(
  "/api/admin/upload-image",
  adminAuth,
  (req, res, next) => {
    upload.single("image")(req, res, error => {
      if (error) {
        return res.status(400).json({
          error: error.message || "Image upload error."
        });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      if (
        !process.env.CLOUDINARY_CLOUD_NAME ||
        !process.env.CLOUDINARY_API_KEY ||
        !process.env.CLOUDINARY_API_SECRET
      ) {
        return res.status(503).json({
          error: "Image storage is not configured."
        });
      }

      if (!req.file) {
        return res.status(400).json({
          error: "Please choose an image."
        });
      }

      const result = await uploadImageToCloudinary(req.file.buffer);

      res.status(201).json({
        success: true,
        url: result.secure_url,
        public_id: result.public_id
      });
    } catch (error) {
      console.error("Image upload error:", error.message);
      res.status(500).json({
        error: "Could not upload image."
      });
    }
  }
);

// ======================================
// APP IMAGE UPLOAD
// ======================================

app.post(
  "/api/admin/app-image",
  adminAuth,
  (req, res, next) => {
    upload.single("image")(req, res, error => {
      if (error) {
        return res.status(400).json({
          error: error.message || "Image upload error."
        });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: "অ্যাপের ছবি নির্বাচন করুন।"
        });
      }

      const result = await uploadImageToCloudinary(
        req.file.buffer,
        "skypay/apps"
      );

      res.status(201).json({
        success: true,
        url: result.secure_url,
        public_id: result.public_id
      });
    } catch (error) {
      console.error("App image upload error:", error.message);
      res.status(500).json({
        error: "অ্যাপের ছবি আপলোড করা যায়নি।"
      });
    }
  }
);
