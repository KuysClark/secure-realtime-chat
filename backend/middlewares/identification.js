const jwt = require('jsonwebtoken')

exports.identifier = (req, res, next) => {
    let token; // Variable para sa token
    
    // Check kung saan kukunin ang token
    if(req.headers.client === 'not-browser') {
        // Mobile app - token nasa headers
        token = req.headers.authorization;
    } else {
        // Browser - token nasa cookies
        token = req.cookies.Authorization;
    }

    // Kapag walang token, huwag magpatuloy
    if(!token) {
        return res.status(401).json({success: false, message:'Unauthorized'});
    }

    try {
        // Tanggalin ang "Bearer " prefix
        const userToken = token.split(' ')[1];
        
        // I-verify ang token gamit ang secret key
        // Kapag valid → returns decoded user data
        // Kapag invalid → throws error agad
        const decoded = jwt.verify(userToken, process.env.TOKEN_SECRET);

        // Ilagay ang user data sa request object Para magamit sa lahat ng susunod na functions or maging cenralized itong data na ito sa mga holder ng identifiers
        req.user = decoded;
        
        // Magpatuloy sa susunod na middleware/route
        next();
        
    } catch(error) {
        // Dito papasok kapag invalid/expired token
        console.error('Auth error:', error.message);
        
        // IMPORTANT: Mag-send ng response sa client!
        return res.status(401).json({
            success: false, 
            message: 'Invalid or expired token'
        });
    }
}