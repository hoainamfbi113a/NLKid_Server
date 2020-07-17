const express = require('express');
var router = express.Router();
const mongoose = require('mongoose');
var Games = require('../models/gamemodel');
var gameContentSchema = require('../models/gamecontentmodel');
var multer = require("multer");
var upload = multer({dest:'./public/uploads/game'})
    const path = require('path');
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "./public/uploads/game");
    },
    filename: (req, file, cb) => {
        const fileName = file.originalname.toLowerCase().split(' ').join('-');
        cb(null,Date.now()+ '-' + fileName)
    }
});
var upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype == "image/png" || file.mimetype == "image/jpg" || file.mimetype == "image/jpeg") {
            cb(null, true);
        } else {
            cb(null, false);
            return cb(new Error('Only .png, .jpg and .jpeg format allowed!'));
        }
    }
});
router.get('/', (req, res) => {
    res.render("new/addOrEdit");

});
router.post('/',upload.fields([{
    name: 'imgQuestionA',
    maxCount: 1,
}, {
    name: 'imgQuestionB'
},
{
    name: 'imgQuestionC'
}
]), (req, res,next) => {
    // console.log("ID: ");
    if (req.body._id === ''|| req.body._id === undefined) {
        // console.log(req.files['imgQuestionA'][0].path)
        // console.log(req.files['imgQuestionB'])
        // console.log(req.file);
        let games = new Games();
        // console.log(req.body.vocabularygame+"aaa");
        games.categoryvocabulary = req.body.categoryvocabulary;
        games.vocabularygame = req.body.vocabularygame;
        games.spellingvocabulary = req.body.spellingvocabulary;
        games.meaningA = req.body.meaningA;
        games.meaningB = req.body.meaningB;
        games.meaningC = req.body.meaningC;
        games.questionResultRight = req.body.questionResultRight;
        
        if(req.files['imgQuestionA']){
            games.questionResultA.ImgQuestionA = req.files['imgQuestionA'][0].path.split('/').slice(1).join('/');
        }
        else{
            games.questionResultA.ImgQuestionA = "uploads/1593760987298-screen-shot-2020-07-03-at-10.23.15.png"
        }
        if(req.files['imgQuestionB']){
            games.questionResultB.ImgQuestionB = req.files['imgQuestionB'][0].path.split('/').slice(1).join('/');
        }
        else{
            games.questionResultB.ImgQuestionB = "uploads/1593760987298-screen-shot-2020-07-03-at-10.23.15.png"
        }
        if(req.files['imgQuestionC']){
            games.questionResultC.ImgQuestionC = req.files['imgQuestionC'][0].path.split('/').slice(1).join('/');
        }
        else{
            games.questionResultC.ImgQuestionC = "uploads/1593760987298-screen-shot-2020-07-03-at-10.23.15.png"
        }
        games.save((err, doc) => {
            if (!err)
            res.json({ status: 200 });
            else {
                console.log('Error during record insertion :' + err);
            }
        });
    }
    else {// req có id sẽ hiểu là đang update
        // games.title = req.body.title;
        if(req.file){
            req.body.images = req.file.path.split('/').slice(1).join('/');
        }
        else{
            req.body.images = "uploads/1593760987298-screen-shot-2020-07-03-at-10.23.15.png"
        }
        Games.findOneAndUpdate({ _id: req.body._id },req.body,{new:true},(err,doc)=>{
            if (!err) 
            {
                res.json({ status: 200 });
            }
            else {
            console.log('Error during record update:' + err);
            }
         } );
        }
})
router.get('/list', (req, res) => {//lấy toàn bộ employee
    Games.find((err, docs) => {//tìm toàn bộ 
        if (!err) {
            res.json(docs);
        }
        else {
            console.log('Error in retrieving Games list :' + err);
        };
    });
});
router.get('/generate', (req, res) => {//
    let gameId = []
    let dem = 0;
    let count = 0;
    Games.find((err, docs) => {//tìm toàn bộ 
        if (!err) {
            // res.json(docs);
            docs.sort((a, b) => a.categoryvocabulary > b.categoryvocabulary);
            dem ++;
            if(count<=10){
                gameContentSchema.categoryvocabulary
                gameContentSchema.categoryvocabulary
                gameContentSchema.categoryvocabulary
                gameContentSchema.categoryvocabulary
                gameContentSchema.categoryvocabulary
            }
        }
        else {
            console.log('Error in retrieving Games list :' + err);
        };
    });
});

router.get('/delete/:id', (req, res) => {
    console.log("a"+ req.params.id)
    Games.findByIdAndRemove(req.params.id, (err, doc) => {
        if (!err) {
            res.json({ status: 200 });
        }
        else { console.log('Error in Games delete:' + err); }
    });
});
router.get('/:id', (req, res) => {
    Games.findById(req.params.id, (err, doc) => {
        if (!err) {
            res.json(doc);
        }
        else { console.log('Error in Games update:' + err); }
    });

});

module.exports = router;