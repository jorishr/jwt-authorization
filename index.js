require('dotenv').config();

const   express = require('express'),
        app     = express(),
        jwt     = require('jsonwebtoken'),
        port    = 3000;

app.use(express.json());

//data
const posts = [
    {
        username: 'John Doe',
        title: 'First post!'
    },
    {
        username: 'Eric Eater',
        title: 'Second post!'
    },
    {
        username: 'Bob Builder',
        title: 'Third post!'
    }
];

//basic get route
app.get('/posts', authorizeUser, (req, res) => {
    //authorizeUser gives us access to req.user = user
    //console.log(req.user)
    res.json(posts.filter(post => post.username === req.user.name));
});

/*  
    ########################
    AUTHORIZATION MIDDLEWARE
    ########################
    - get the JWTtoken, verify it and return that user
    
    - the JWT token is available in the headers and is stored afte the keyword: 
    Bearer TOKEN

    - the req.headers['authorization'] is a string we split into an array of 
    substrings, where we access the second value [1]

    - first check if there is and authHeader
    - if there is none, send an error message
    - if there is one, verify it with the SECRET TOKEN

    - the verify function has CALLBACK: (err, user): 
        if verification fails, inform user about invalid token (403) 
        if verification success, set the req.user to the deserialized user object.
    
    - move on with next() middleware
*/
function authorizeUser(req, res, next) {
    //console.log(req.headers)
    const   authHeader  = req.headers['authorization'],
            token       = authHeader && authHeader.split(' ')[1];
    if(token == null){return res.sendStatus(401)};
    jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(403);
        req.user = user;    //this is now available on the route it is applied
        next();
    });
};

app.listen(port, () => console.log(`Server1 listening on port ${port}!`));
