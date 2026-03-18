var express = require("express");
var router = express.Router();
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let fs = require('fs');
let path = require('path');
const { CheckLogin } = require("../utils/authHandler");

// Đọc private key để mã hoá (RS256)
const privateKey = fs.readFileSync(path.join(__dirname, '../private.pem'), 'utf8');

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(username, password, email, "69b0ddec842e41e8160132b8");
        res.send(newUser);
    } catch (error) { res.status(404).send(error.message); }
});

router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) return res.status(404).send({ message: "thong tin dang nhap sai" });
        if (user.lockTime > Date.now()) return res.status(404).send({ message: "ban dang bi ban" });
        
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0; // Đã fix lỗi logic chỗ này
            await user.save();
            
            // Đổi thuật toán mã hoá sang RS256
            let token = jwt.sign({ id: user._id }, privateKey, { algorithm: 'RS256', expiresIn: '1h' });
            res.send({ token: token });
        } else {
            user.loginCount++;
            if (user.loginCount >= 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000;
            }
            await user.save();
            res.status(404).send({ message: "thong tin dang nhap sai" });
        }
    } catch (error) { res.status(404).send({ message: error.message }); }
});

router.get('/me', CheckLogin, function(req, res, next){
    res.send(req.user);
});

// API ĐỔI MẬT KHẨU (Yêu cầu đăng nhập, Validate newpassword)
router.post('/changepassword', CheckLogin, async function(req, res, next) {
    try {
        let { oldpassword, newpassword } = req.body;
        let user = req.user;

        // Validate mật khẩu mới (Ví dụ: Yêu cầu ít nhất 6 ký tự)
        if (!newpassword || newpassword.length < 6) {
            return res.status(400).send({ message: "Mật khẩu mới phải có ít nhất 6 ký tự!" });
        }

        // Kiểm tra mật khẩu cũ
        if (!bcrypt.compareSync(oldpassword, user.password)) {
            return res.status(400).send({ message: "Mật khẩu cũ không chính xác!" });
        }

        // Cập nhật mật khẩu mới
        user.password = newpassword;
        await user.save(); // Middleware pre('save') ở schema sẽ tự băm mật khẩu
        
        res.status(200).send({ message: "Đổi mật khẩu thành công!" });
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

module.exports = router;