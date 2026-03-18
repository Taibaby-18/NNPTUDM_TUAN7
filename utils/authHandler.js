let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
let fs = require('fs');
let path = require('path');

// Đọc public key để giải mã (RS256)
const publicKey = fs.readFileSync(path.join(__dirname, '../public.pem'), 'utf8');

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            if (!req.headers.authorization || !req.headers.authorization.startsWith("Bearer")) {
                return res.status(404).send({ message: "ban chua dang nhap" });
            }
            let token = req.headers.authorization.split(" ")[1];
            
            // Chuyển sang thuật toán RS256
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            
            // Đã fix lỗi Date.now()
            if (result.exp * 1000 < Date.now()) {
                return res.status(404).send({ message: "Token het han" });
            }
            
            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                return res.status(404).send({ message: "ban chua dang nhap" });
            }
            req.user = user;
            next();
        } catch (error) {
            res.status(404).send({ message: "Token khong hop le hoac ban chua dang nhap" });
        }
    }
}