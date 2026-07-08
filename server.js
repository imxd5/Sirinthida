const express = require('express');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
app.use(express.json()); 
app.use(express.static('public')); 

// ตัวแปรจำลองฐานข้อมูล
const users = [];

// ==========================================
// 1. API สำหรับสมัครสมาชิก (Register)
// ==========================================
app.post('/api/register', async (req, res) => {
    try {
        const { Username, Email, Password, confirmPassword } = req.body;

        // 1. ตรวจสอบว่ากรอกข้อมูลครบถ้วนไหม
        if (!Username || !Email || !Password || !confirmPassword) {
            return res.status(400).json({ message: "กรุณากรอกข้อมูลให้ครบถ้วน" });
        }

        // 2. ตรวจสอบว่ารหัสผ่านและการยืนยันรหัสผ่านตรงกันไหม
        if (Password !== confirmPassword) {
            return res.status(400).json({ message: "รหัสผ่านและการยืนยันรหัสผ่านไม่ตรงกัน" });
        }

        // 3. ตรวจสอบรูปแบบอีเมล
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(Email)) {
            return res.status(400).json({ message: "รูปแบบอีเมลไม่ถูกต้อง" });
        }
        
        // 4. ตรวจสอบความยาวรหัสผ่าน
        if (Password.length < 8) {
            return res.status(400).json({ message: "รหัสผ่านต้องมีความยาวอย่างน้อย 8 ตัวอักษรขึ้นไป" });
        }

        // 5. ตรวจสอบข้อมูลซ้ำในระบบ
        const userExists = users.find(user => user.Username === Username || user.Email === Email);
        if (userExists) {
            if (userExists.Username === Username      ) {
                return res.status(400).json({ message: "ชื่อผู้ใช้นี้ถูกใช้งานแล้ว" });
            }
            if (userExists.Email === Email) {
                return res.status(400).json({ message: "อีเมลนี้ถูกใช้งานแล้ว" });
            }
        }

        // 6. เข้ารหัสผ่านก่อนบันทึก
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(Password, salt);

        // 7. บันทึกข้อมูลผู้ใช้ใหม่
        const newUser = {
            id: Date.now(),
            Username: Username,
            Email: Email,
            password: hashedPassword
        };
        users.push(newUser);

        res.status(201).json({ message: "สมัครสมาชิกสำเร็จแล้ว!" });

    } catch (error) {
        res.status(500).json({ message: "เกิดข้อผิดพลาดบนเซิร์ฟเวอร์" });
    }
});

// ==========================================
// 2. API สำหรับเข้าสู่ระบบ (Login)
// ==========================================
app.post('/api/login', async (req, res) => {
    try {
        const { Username, Email, Password, confirmPassword } = req.body || {};

        // 1. ตรวจสอบว่ากรอกข้อมูลครบถ้วนไหม
        if (!Username || !Password) {
            return res.status(400).json({ message: "กรุณากรอกชื่อผู้ใช้และรหัสผ่าน" });
        }

        // 2. ถ้าส่ง confirmPassword มาให้ตรวจความตรงกันด้วย
        if (confirmPassword !== undefined && confirmPassword !== '' && Password !== confirmPassword) {
            return res.status(400).json({ message: "รหัสผ่านและการยืนยันรหัสผ่านไม่ตรงกัน" });
        }

        // 3. ค้นหาผู้ใช้โดยใช้ Username ก่อน และใช้ Email ถ้ามีข้อมูล
        const user = Email
            ? users.find(user => user.Username === Username && user.Email === Email)
            : users.find(user => user.Username === Username);

        if (!user) {
            return res.status(400).json({ message: "ชื่อผู้ใช้หรืออีเมลไม่ถูกต้อง" });
        }

        // 4. ตรวจสอบรหัสผ่านที่ป้อนเข้ามาเทียบกับแฮชในระบบ
        const isMatch = await bcrypt.compare(Password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "รหัสผ่านไม่ถูกต้อง" });
        }

        // เข้าสู่ระบบสำเร็จ
        res.status(200).json({ 
            message: "เข้าสู่ระบบสำเร็จ!", 
            user: { id: user.id, Username: user.Username, Email: user.Email } 
        });

    } catch (error) {
        res.status(500).json({ message: "เกิดข้อผิดพลาดบนเซิร์ฟเวอร์" });
    }
});

// เปิดใช้งาน Server ที่ Port 3000 (หรือพอร์ตที่กำหนดจาก environment)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running http://localhost:${PORT}`);
});