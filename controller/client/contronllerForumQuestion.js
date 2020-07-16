const express = require('express');
var router = express.Router();
var forumQuestion = require("../../models/forumQuestionModel")

router.get('/', (req, res) => {
    res.render("forumquestion/addOrEdit", {
        forumquestion:[]
    });
});
router.post('/', (req, res) => {
    // console.log(req.body._id+'  a');
    if (req.body._id == '' || req.body._id === undefined)
        insertRecord(req, res);
        else
        updateRecord(req, res);
});
function insertRecord(req, res) {//thêm dữ liệu
    var forumquestion = new forumQuestion();//tạo một forumQuestion mới
    console.log(req.body.titleForumQuestion+"forum");
    console.log(req.body.memberForumQuestionMemberName+"name");
    forumquestion.titleForumQuestion = req.body.titleForumQuestion;
    
    forumquestion.classForumQuestion = req.body.classForumQuestion;
    forumquestion.memberForumQuestion.avatarContentImg = req.body.avatarContentImg;
    forumquestion.memberForumQuestion.memberName = req.body.memberForumQuestionMemberName;
    // forumquestion.forumquestionResultA = req.body.forumquestionResultA;
    // forumquestion.forumquestionResultB = req.body.forumquestionResultB;
    // forumquestion.forumquestionResultC = req.body.forumquestionResultC;
    // forumquestion.forumquestionResultD = req.body.forumquestionResultD;
    // forumquestion.forumquestionResultRight = req.body.forumquestionResultRight;
    forumquestion.save((err, doc) => {//thêm dữ liệu vào database
        if (!err)//nếu thành công
            // res.redirect('forumQuestion/list');
            console.log('them thanh cong forum');
        else {//nếu lỗi
                console.log('Error during record insertion : ' + err);
        }
    });
}

function updateRecord(req, res) {//tiến hành update dư liệu
    forumQuestion.findOneAndUpdate({ _id: req.body._id }, req.body, { new: true }, (err, doc) => {//tìm user 
        //trùng với ID và update
        if (!err) { res.redirect('/admin/forumquestion/list'); }//tìm thấy và tiến hành update
        else {//không tìm thấy và không update
                console.log('Error during record update : ' + err);
        }
    });
}


router.get('/list', (req, res) => {//lấy toàn bộ forumQuestion
    forumQuestion.find((err, docs) => {//tìm toàn bộ 
        if (!err) {
            res.json(docs);
        }
        else {
            console.log('Error in retrieving forumQuestion list :' + err);
        }
    });
});
router.get('/list/:id', (req, res) => {//lấy toàn bộ forumQuestion
    console.log(req.params.id);
    Examcontent.find({examId:req.params.id},(err, docs) => {//tìm toàn bộ 
        if (!err) {
            res.json(docs);
           // console.log(docs);
        }
        else {
            console.log('Error in retrieving forumQuestion list :' + err);
        }
    });
});
router.get('/:id', (req, res) => {//tìm id để tiến hành update
    console.log('update1');
    forumQuestion.findById(req.params.id, (err, doc) => {
        if (!err) {//không có lỗi thì điền vào form dữ liệu update
            res.json(doc);
        }
        
    });
});

router.get('/delete/:id', (req, res) => {//xóa forumQuestion
    forumQuestion.findByIdAndRemove(req.params.id, (err, doc) => {//tìm và xóa dữ liệu
        if (!err) {//không có lỗi khi tìm và tìm thấy
            res.redirect('/admin/forumquestion/list');
        }
        else { console.log('Error in forumQuestion delete :' + err); }//có lỗi và xuất lỗi ra
    });
});

module.exports = router;