// Database Table for Admin Settings (বিকাশ নম্বর, ডিপোজিট, উইথড্র ও প্রোডাক্টের মেয়াদ নিয়ন্ত্রণের জন্য)
pool.query(`
  CREATE TABLE IF NOT EXISTS admin_settings (
    id SERIAL PRIMARY KEY,
    setting_key VARCHAR(50) UNIQUE NOT NULL,
    setting_value TEXT NOT NULL
  )
`).then(() => {
  console.log("Admin Settings table ready.");
}).catch(err => console.error("Settings table error:", err));

// --- ADMIN & USER APIs ---

// ১. ইউজারের জন্য সকল সেটিংস (বিকাশ নম্বর, প্রোডাক্ট মেয়াদ ইত্যাদি) ফেচ করার API
app.get('/api/settings', async (req, res) => {
  try {
    const result = await pool.query('SELECT setting_key, setting_value FROM admin_settings');
    const settings = {};
    result.rows.forEach(row => {
      settings[row.setting_key] = row.setting_value;
    });
    res.json({ success: true, settings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'ডেটা লোড করতে সমস্যা হয়েছে।' });
  }
});

// ২. এডমিন প্যানেল থেকে যেকোনো কিছু আপডেট বা এডিট করার API
app.post('/api/admin/update-settings', async (req, res) => {
  const { key, value } = req.body; // যেমন: key = 'bkash_number', value = '017xxxxxxxx'
  try {
    await pool.query(`
      INSERT INTO admin_settings (setting_key, setting_value) 
      VALUES ($1, $2) 
      ON CONFLICT (setting_key) 
      DO UPDATE SET setting_value = $2
    `, [key, value]);
    
    res.json({ success: true, message: 'সফলভাবে আপডেট করা হয়েছে!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'আপডেট করতে সমস্যা হয়েছে।' });
  }
});
