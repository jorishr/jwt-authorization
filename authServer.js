require('dotenv').config();

const   express = require('express'),
        app     = express(),
        jwt     = require('jsonwebtoken'),
        port    = 3500;

app.use(express.json());

/* 
    ###################
    REFRESH TOKEN ROUTE
    ###################
    - check if the token exists, if not report 401
    - check if the token is valid (part of our db), if not reject with 403
    - if exists and is valid. verify the JWT refresToken with the SECRET
    - upon succesfull verification, generate a new accessToken
    - note: the user object generated through the verification process has
    many additional properties. We only pass in what we need: {name: user.name}
*/
let refresTokens = [];

app.post('/token', (req, res) => {
    const refreshToken = req.body.token;
    if(refreshToken == null) return res.sendStatus(401);
    if(!refresTokens.includes(refreshToken)) return res.sendStatus(403);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN, (err, user) => {
        if(err) return res.sendStatus(403);
        const newAccessToken = generateAccessToken({ name: user.name});
        res.json({ accessToken: newAccessToken});
    });
});
/* 
    ########################
    DELETE TOKEN UPON LOGOUT
    ########################
    - in theory the user could keep on refreshing the token forever
    - upon logout, delete the refreshToken from the refreshTokens array or db
    - use .filter to create a new array without the one of the current user 
    that is logging out.
    - send success code
*/

app.delete('/logout', (req, res) => {
    refresTokens = refresTokens.filter(token => token !== req.body.token);
    //console.log('delete token success')
    res.sendStatus(204);
});

/* 
    #######################
    INITIATE JWT UPON LOGIN
    #######################
    - get the username to create a user object
    
    - this object is serialized as the payload with JWT, using the TOKEN_SECRET
    
    - store the result as the accesstoken, repeat for REFRESH TOKEN.
    
    - thus now each time user is loggedin correctly, an accessToken is generated, 
    which has the user data stored inside it for future reference.

    - return both accessToken and refreshToken to the user as the res.json() 
    whereby the accessToken expires in 15s, blocking access to protected routes
    
    - push the newly created REFRESH TOKEN to the locally stored ARRAY, in 
    production you store this in a caching service as REDIS or a database.

*/
app.post('/login', (req, res) => {
    //authenticate user code
    //
    //authorization with JWT
    const   username     = req.body.username,
            user         = {name: username},
            accessToken  = generateAccessToken(user);
            refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN);
            refresTokens.push(refreshToken);
    res.json({accessToken: accessToken, refreshToken: refreshToken});
}); 

function generateAccessToken(user){
    return jwt.sign(user, process.env.TOKEN_SECRET, { expiresIn: '30s' });
};

app.listen(port, () => console.log(`AuthServer listening on port ${port}!`));