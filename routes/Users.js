const express = require('express')
const users = express.Router()
const cors = require('cors')//cho phép truy cập
const jwt = require('jsonwebtoken')//sử dụng token
const bcrypt = require('bcrypt')//dùng để hash function

const User = require('../models/User')
users.use(cors());

process.env.SECRET_KEY = 'secret'//secret môi trường

users.post('/register', (req, res) => {
  const today = new Date()
  const userData = //nhận dữ liệu từ react gửi qua
  {
    first_name: req.body.first_name,
    last_name: req.body.last_name,
    email: req.body.email,
    password: req.body.password,
    created: today
  }
  User.findOne({//Kiểm tra email người dùng đăng ký đã tồn tại hay không
    email: req.body.email
  })
    .then(user => {
      if (!user) {//Không trùng với bất kỳ email nào và tiến hành đăng ký
        bcrypt.hash(req.body.password, 10, (err, hash) => {//hash mật khẩu người dùng đăng ký
          userData.password = hash
          User.create(userData)//tiến hành tạo tài khoản 
            .then(user => {
              res.json({ status: user.email + 'Registered!' })//trả lại cho reactjs nếu đăng ký thành công
            })
            .catch(err => {
              res.send('error: ' + err)//trả ra lỗi
            })
        })
      } else {
        res.send('User already exists')//xuất ra lỗi nếu email đã tồn tại
      }
    })
    .catch(err => {
      res.send('error: ' + err)
    })
})

users.post('/login', (req, res) => {
  User.findOne({
    email: req.body.email
  })
    .then(user => {
      if (user) {
        if (bcrypt.compareSync(req.body.password, user.password)) {//so sanh mat khau da hash
          // Passwords match
          const payload = {//luu vao payload de gui token
            _id: user._id,
            first_name: user.first_name,
            last_name: user.last_name,
            email: user.email
          }
          let token = jwt.sign(payload, process.env.SECRET_KEY, {//dang ky token user
            expiresIn: '1h'//thoi gian ton tai token
          })
      
          res.send(token)
       //   console.log('exist');
        } else {
          // Passwords don't match
          res.send('User not exists')
        }
      } else {
        res.send('User not exists')
      }
    })
    .catch(err => {
      res.send(err)
    })
})

users.get('/profile', (req, res) => {
  var decoded = jwt.verify(req.headers['authorization'], process.env.SECRET_KEY)//dung de xac minh
  
  User.findOne({
    _id: decoded._id
  })
    .then(user => {
      if (user) {
        res.json(user)
      } else {
        res.send('User does not exist')
      }
    })
    .catch(err => {
      res.send('error: ' + err)
    })
})

module.exports = users
