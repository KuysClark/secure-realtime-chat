// Line 1: Import ang 'hash' function from bcryptjs library
const { hash, compare } = require("bcryptjs");
const {createHmac} = require('crypto')
// Purpose: Kunin lang yung 'hash' function, hindi buong bcryptjs library
// bcryptjs = library for password hashing (security)

// Line 3: Export ang 'doHash' function para magamit sa ibang files
exports.doHash = async (value, saltValue) => {
    // exports.doHash = gawing available sa ibang files
    // async = kailangan dahil may 'await' sa loob (hashing takes time)
    // value = yung password na ihahash (example: "MyPass123")
    // saltValue = number for security (example: 12) - mas mataas, mas secure pero mas mabagal
    
    // Line 4: I-hash ang value using bcryptjs
    const result = await hash(value, saltValue);
    // await = hintayin matapos ang hashing bago magproceed
    // hash() = bcryptjs function para mag-hash
    // Example result: "$2a$12$kajshdkjahsdkjhasd7123..."
    
    // Line 5: I-return ang hashed value
    return result;
    // This returns the hashed password para magamit sa authController
};

exports.doHashValidation = (value, hashedValue) =>{
    const result = compare(value, hashedValue);
    return result;
}

exports.hmacProcess = (value,key) => {
    const result = createHmac('sha256', key).update(value).digest('hex')
    return result
}