//
//  RESTManager.swift
//  CosyncJWTiOS
//
//  Created by Richard Krueger on 8/6/20.
//  Copyright © 2020 cosync. All rights reserved.
//

import Foundation
import CommonCrypto

extension String {

    func md5() -> String {

        let context = UnsafeMutablePointer<CC_MD5_CTX>.allocate(capacity: 1)
        var digest = Array<UInt8>(repeating:0, count:Int(CC_MD5_DIGEST_LENGTH))
        CC_MD5_Init(context)
        CC_MD5_Update(context, self, CC_LONG(self.lengthOfBytes(using: String.Encoding.utf8)))
        CC_MD5_Final(&digest, context)
        context.deallocate()
        var hexString = ""
        for byte in digest {
            hexString += String(format:"%02x", byte)
        }

        return hexString
    }
}


public class CosyncJWTRest {
    
    // Configuration
    public var appToken: String?
    public var cosyncRestAddress: String?
        
    // Login credentials
    public var jwt: String?
    public var accessToken: String?
    
    // complete signup credentials
    public var signedUserToken: String?
    
    // Logged in user information
    public var handle: String?
    public var metaData: [String:Any]?
    public var lastLogin: Date?
    
    // application data
    public var appName: String?
    public var twoFactorVerification: String?
    var passwordFilter: Bool?
    var passwordMinLength: Int?
    var passwordMinUpper: Int?
    var passwordMinLower: Int?
    var passwordMinDigit: Int?
    var passwordMinSpecial: Int?
    
    var appData: [String:Any]?
    
    static let loginPath = "api/appuser/login"
    static let signupPath = "api/appuser/signup"
    static let completeSignupPath = "api/appuser/completeSignup"
    static let getUserPath = "api/appuser/getUser"
    static let setPhonePath = "api/appuser/setPhone"
    static let verifyPhonePath = "api/appuser/verifyPhone"
    static let forgotPasswordPath = "api/appuser/forgotPassword"
    static let resetPasswordPath = "api/appuser/resetPassword"
    static let changePasswordPath = "api/appuser/changePassword"
    static let getApplicationPath = "api/appuser/getApplication"
    static let invitePath = "api/appuser/invite"
    static let registerPath = "api/appuser/register"

    public static let shared = CosyncJWTRest()
    
    // Configure
    public func configure(appToken: String, cosyncRestAddress: String = "") {
        self.appToken = appToken
        if cosyncRestAddress == "" {
            self.cosyncRestAddress = "https://rest.cosync.net"

        } else {
            self.cosyncRestAddress = cosyncRestAddress
        }
    }

    // Login into CosyncJWT
    public func login(_ handle: String, password: String, onCompletion completion: @escaping (Error?) -> Void) {
        
        if  let appToken = self.appToken,
            let cosyncRestAddress = self.cosyncRestAddress {
            
            CosyncJWTRest.shared.getApplication(onCompletion: { (err) in
                
                if let error = err {
                    completion(error)
                } else {
                    let restPath = cosyncRestAddress
                    let appToken = appToken
                    
                    let config = URLSessionConfiguration.default

                    let session = URLSession(configuration: config)
                    
                    let url = URL(string: "\(restPath)/\(CosyncJWTRest.loginPath)")!
                    var urlRequest = URLRequest(url: url)
                    urlRequest.httpMethod = "POST"
                    urlRequest.allHTTPHeaderFields = ["app-token": appToken]

                    // your post request data
                    var requestBodyComponents = URLComponents()
                    requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                        URLQueryItem(name: "password", value: password.md5())]
                    
                    urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

                    let task = session.dataTask(with: urlRequest) { data, response, error in
                    
                        // ensure there is no error for this HTTP response
                        let errorResponse = CosyncJWTError.checkResponse(data: data, response: response, error: error)
                        guard errorResponse == nil  else {
                            completion(errorResponse)
                            return
                        }

                        // ensure there is data returned from this HTTP response
                        guard let content = data else {
                            completion(CosyncJWTError.internalServerError)
                            return
                        }
                        
                        // serialise the data / NSData object into Dictionary [String : Any]
                        guard let json = (try? JSONSerialization.jsonObject(with: content, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                            completion(CosyncJWTError.internalServerError)
                            return
                        }
                        
                        if let jwt = json["jwt"] as? String,
                           let accessToken = json["access-token"] as? String {
                            
                            self.jwt = jwt
                            self.accessToken = accessToken

                            completion(nil)
                        } else {
                            completion(CosyncJWTError.internalServerError)
                        }
                    }
                    
                    // execute the HTTP request
                    task.resume()
                }
            })

        } else {
            completion(CosyncJWTError.cosyncJWTConfiguration)
        }
        
        
    }
    
    // Singup into CosyncJWT
    public func signup(_ handle: String, password: String, metaData: String?, onCompletion completion: @escaping (Error?) -> Void) {

        if  let appToken = self.appToken,
            let cosyncRestAddress = self.cosyncRestAddress {
            
            CosyncJWTRest.shared.getApplication(onCompletion: { (err) in
                
                if let error = err {
                    completion(error)
                } else {
                    
                    if self.checkPassword(password) {
                        let restPath = cosyncRestAddress
                        let appToken = appToken
                        
                        let config = URLSessionConfiguration.default

                        let session = URLSession(configuration: config)
                        
                        let url = URL(string: "\(restPath)/\(CosyncJWTRest.signupPath)")!
                        var urlRequest = URLRequest(url: url)
                        urlRequest.httpMethod = "POST"
                        urlRequest.allHTTPHeaderFields = ["app-token": appToken]

                        // your post request data
                        var requestBodyComponents = URLComponents()
                        if let metaData = metaData {
                            requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                                URLQueryItem(name: "password", value: password.md5()),
                                                                URLQueryItem(name: "metaData", value: metaData)]

                        } else {
                            requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                                URLQueryItem(name: "password", value: password.md5())]
                        }
                        
                        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

                        let task = session.dataTask(with: urlRequest) { data, response, error in
                        
                            // ensure there is no error for this HTTP response
                            let errorResponse = CosyncJWTError.checkResponse(data: data, response: response, error: error)
                            guard errorResponse == nil  else {
                                completion(errorResponse)
                                return
                            }

                            // ensure there is data returned from this HTTP response
                            guard let content = data else {
                                completion(CosyncJWTError.internalServerError)
                                return
                            }
                            
                            let str = String(decoding: content, as: UTF8.self)
                            
                            if str == "true" {
                                completion(nil)
                            } else {
                                completion(CosyncJWTError.internalServerError)
                            }

                        }
                        
                        // execute the HTTP request
                        task.resume()
                    } else {
                        completion(CosyncJWTError.invalidPassword)
                    }
                }
            })
            
        } else {
            completion(CosyncJWTError.cosyncJWTConfiguration)
        }

    }
    
    public func checkPassword(_ password: String) -> Bool {
        
        if let passwordFilter = self.passwordFilter,
               passwordFilter {
            
            if  let passwordMinLength = self.passwordMinLength,
                password.count < passwordMinLength {
                return false
            }
            
            if  let passwordMinUpper = self.passwordMinUpper {
                let characters = Array(password)
                var count = 0
                for c in characters {
                    let cs = String(c)
                    if cs == cs.uppercased() && cs != cs.lowercased() {
                        count += 1
                    }
                }
                if count < passwordMinUpper {
                    return false
                }
                
            }
            
            if  let passwordMinLower = self.passwordMinLower {
                let characters = Array(password)
                var count = 0
                for c in characters {
                    let cs = String(c)
                    if cs == cs.lowercased() && cs != cs.uppercased() {
                        count += 1
                    }
                }
                if count < passwordMinLower {
                    return false
                }
            }
            
            if  let passwordMinDigit = self.passwordMinDigit {
                let characters = Array(password)
                var count = 0
                for c in characters {
                    if c.isASCII && c.isNumber {
                        count += 1
                    }
                }
                if count < passwordMinDigit {
                    return false
                }
            }
                
            if  let passwordMinSpecial = self.passwordMinSpecial {
                let characterset = CharacterSet(charactersIn: "@%+\\/‘!#$^?:()[]~`-_.,")
                
                let characters = password.unicodeScalars
                var count = 0
                for c in characters {
                    if characterset.contains(c) {
                        count += 1
                    }
                }
                if count < passwordMinSpecial {
                    return false
                }
            }
        }
        
        return true
    }
    
    // Complete Singup into CosyncJWT
    public func completeSignup(_ handle: String, code: String, onCompletion completion: @escaping (Error?) -> Void) {
        
        if  let appToken = self.appToken,
            let cosyncRestAddress = self.cosyncRestAddress {
            
            let restPath = cosyncRestAddress
            let appToken = appToken
            
            let config = URLSessionConfiguration.default

            let session = URLSession(configuration: config)
            
            let url = URL(string: "\(restPath)/\(CosyncJWTRest.completeSignupPath)")!
            var urlRequest = URLRequest(url: url)
            urlRequest.httpMethod = "POST"
            urlRequest.allHTTPHeaderFields = ["app-token": appToken]

            // your post request data
            var requestBodyComponents = URLComponents()
            
            requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                URLQueryItem(name: "code", value: code)]

            urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

            let task = session.dataTask(with: urlRequest) { data, response, error in
            
                let errorResponse = CosyncJWTError.checkResponse(data: data, response: response, error: error)
                guard errorResponse == nil  else {
                    completion(errorResponse)
                    return
                }
                
                // ensure there is data returned from this HTTP response
                guard let content = data else {
                    completion(CosyncJWTError.internalServerError)
                    return
                }
                
                // serialise the data / NSData object into Dictionary [String : Any]
                guard let json = (try? JSONSerialization.jsonObject(with: content, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                    completion(CosyncJWTError.internalServerError)
                    return
                }
                
                if let jwt = json["jwt"] as? String,
                   let accessToken = json["access-token"] as? String,
                   let signedUserToken = json["signed-user-token"] as? String {
                    
                    self.jwt = jwt
                    self.accessToken = accessToken
                    self.signedUserToken = signedUserToken

                    completion(nil)
                } else {
                    
                    completion(CosyncJWTError.internalServerError)
                }

            }
            
            // execute the HTTP request
            task.resume()
            
        } else {
            completion(CosyncJWTError.cosyncJWTConfiguration)
        }

    }
    
    // Get logged in user data from CosyncJWT
    public func getUser(onCompletion completion: @escaping (Error?) -> Void) {
        
        if  let cosyncRestAddress = self.cosyncRestAddress {
            
            let restPath = cosyncRestAddress
            if let accessToken = self.accessToken {
                
                let config = URLSessionConfiguration.default
                config.httpAdditionalHeaders = ["access-token": accessToken]

                let session = URLSession(configuration: config)
                
                let url = URL(string: "\(restPath)/\(CosyncJWTRest.getUserPath)")!
                
                let urlRequest = URLRequest(url: url)
                
                let task = session.dataTask(with: urlRequest) { data, response, error in
                
                    // ensure there is no error for this HTTP response
                    let errorResponse = CosyncJWTError.checkResponse(data: data, response: response, error: error)
                    guard errorResponse == nil  else {
                        completion(errorResponse)
                        return
                    }

                    // ensure there is data returned from this HTTP response
                    guard let content = data else {
                        completion(CosyncJWTError.internalServerError)
                        return
                    }
                    
                    // serialise the data / NSData object into Dictionary [String : Any]
                    guard let json = (try? JSONSerialization.jsonObject(with: content, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                        completion(CosyncJWTError.internalServerError)
                        return
                    }
                    
                    if let handle = json["handle"] as? String {
                        self.handle = handle
                    }
                    
                    
                    if let metaData = json["metaData"] as? [String: Any] {
                        self.metaData = metaData
                    }
                    
                    if let lastLogin = json["lastLogin"] as? String {
                        
                        let dateFormatter = DateFormatter()
                        dateFormatter.locale = .init(identifier: "en_US_POSIX")
                        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
                        
                        let date = dateFormatter.date(from:lastLogin)
                        if let date = date {
                            self.lastLogin = date
                        }
                    }
                    
                    completion(nil)

                }
                
                // execute the HTTP request
                task.resume()
                
            } else {
                completion(CosyncJWTError.internalServerError)
            }
     
            
        } else {
            completion(CosyncJWTError.cosyncJWTConfiguration)
        }
        
    }
    
    // Set the phone number for the current user from CosyncJWT
    public func setPhone(_ phoneNumber: String, onCompletion completion: @escaping (Error?) -> Void) {
        
        if  let cosyncRestAddress = self.cosyncRestAddress {
            
            let restPath = cosyncRestAddress
            if let accessToken = self.accessToken {
                
                let config = URLSessionConfiguration.default
                config.httpAdditionalHeaders = ["access-token": accessToken]
                NSLog("access token '\(accessToken)'")

                let session = URLSession(configuration: config)
                
                let url = URL(string: "\(restPath)/\(CosyncJWTRest.setPhonePath)")!
                var urlRequest = URLRequest(url: url)
                
                urlRequest.httpMethod = "POST"
                urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

                // your post request data
                var requestBodyComponents = URLComponents()
                
                requestBodyComponents.queryItems = [URLQueryItem(name: "phone", value: phoneNumber)]

                urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

                
                let task = session.dataTask(with: urlRequest) { data, response, error in
                
                    // ensure there is no error for this HTTP response
                    let errorResponse = CosyncJWTError.checkResponse(data: data, response: response, error: error)
                    guard errorResponse == nil  else {
                        completion(errorResponse)
                        return
                    }

                    // ensure there is data returned from this HTTP response
                    guard let content = data else {
                        completion(CosyncJWTError.internalServerError)
                        return
                    }
                    
                    let str = String(decoding: content, as: UTF8.self)
                    
                    if str == "true" {
                        completion(nil)
                    } else {
                        completion(CosyncJWTError.internalServerError)
                    }
                    
                    completion(nil)

                }
                
                // execute the HTTP request
                task.resume()
                
            } else {
                completion(CosyncJWTError.internalServerError)
            }
            
        } else {
            completion(CosyncJWTError.cosyncJWTConfiguration)
        }
        

    }
    
    // Set the phone number for the current user from CosyncJWT
    public func verifyPhone(_ code: String, onCompletion completion: @escaping (Error?) -> Void) {
        
        if  let cosyncRestAddress = self.cosyncRestAddress {
            
            let restPath = cosyncRestAddress
            if let accessToken = self.accessToken {
                
                let config = URLSessionConfiguration.default
                config.httpAdditionalHeaders = ["access-token": accessToken]
                NSLog("access token '\(accessToken)'")

                let session = URLSession(configuration: config)
                
                let url = URL(string: "\(restPath)/\(CosyncJWTRest.verifyPhonePath)")!
                var urlRequest = URLRequest(url: url)
                
                urlRequest.httpMethod = "POST"
                urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

                // your post request data
                var requestBodyComponents = URLComponents()
                
                requestBodyComponents.queryItems = [URLQueryItem(name: "code", value: code)]

                urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

                
                let task = session.dataTask(with: urlRequest) { data, response, error in
                
                    // ensure there is no error for this HTTP response
                    let errorResponse = CosyncJWTError.checkResponse(data: data, response: response, error: error)
                    guard errorResponse == nil  else {
                        completion(errorResponse)
                        return
                    }

                    // ensure there is data returned from this HTTP response
                    guard let content = data else {
                        completion(CosyncJWTError.internalServerError)
                        return
                    }
                    
                    let str = String(decoding: content, as: UTF8.self)
                    
                    if str == "true" {
                        completion(nil)
                    } else {
                        completion(CosyncJWTError.internalServerError)
                    }
                    
                    completion(nil)

                }
                
                // execute the HTTP request
                task.resume()
                
            } else {
                completion(CosyncJWTError.internalServerError)
            }
        } else {
            completion(CosyncJWTError.cosyncJWTConfiguration)
        }
        
 
    }
    
    
    // Forgot Password into CosyncJWT
    public func forgotPassword(_ handle: String, onCompletion completion: @escaping (Error?) -> Void) {
        
        if  let appToken = self.appToken,
            let cosyncRestAddress = self.cosyncRestAddress {
            
            let restPath = cosyncRestAddress
            let appToken = appToken
            
            let config = URLSessionConfiguration.default

            let session = URLSession(configuration: config)
            
            let url = URL(string: "\(restPath)/\(CosyncJWTRest.forgotPasswordPath)")!
            var urlRequest = URLRequest(url: url)
            urlRequest.httpMethod = "POST"
            urlRequest.allHTTPHeaderFields = ["app-token": appToken]

            // your post request data
            var requestBodyComponents = URLComponents()
            
            requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle)]

            urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

            let task = session.dataTask(with: urlRequest) { data, response, error in
            
                // ensure there is no error for this HTTP response
                let errorResponse = CosyncJWTError.checkResponse(data: data, response: response, error: error)
                guard errorResponse == nil  else {
                    completion(errorResponse)
                    return
                }
                
                // ensure there is data returned from this HTTP response
                guard let content = data else {
                    completion(CosyncJWTError.internalServerError)
                    return
                }
                
                let str = String(decoding: content, as: UTF8.self)
                
                if str == "true" {
                    completion(nil)
                } else {
                    completion(CosyncJWTError.internalServerError)
                }
            }
            
            // execute the HTTP request
            task.resume()
            
        } else {
            completion(CosyncJWTError.cosyncJWTConfiguration)
        }
    }
    
    // Reset password into CosyncJWT
    public func resetPassword(_ handle: String, password: String, code: String, onCompletion completion: @escaping (Error?) -> Void) {
        
        
        if  let appToken = self.appToken,
            let cosyncRestAddress = self.cosyncRestAddress {
            
            if self.checkPassword(password) {
                
                let restPath = cosyncRestAddress
                let appToken = appToken
                
                let config = URLSessionConfiguration.default

                let session = URLSession(configuration: config)
                
                let url = URL(string: "\(restPath)/\(CosyncJWTRest.resetPasswordPath)")!
                var urlRequest = URLRequest(url: url)
                urlRequest.httpMethod = "POST"
                urlRequest.allHTTPHeaderFields = ["app-token": appToken]

                // your post request data
                var requestBodyComponents = URLComponents()
                
                requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                    URLQueryItem(name: "password", value: password.md5()),
                                                    URLQueryItem(name: "code", value: code)]

                urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

                let task = session.dataTask(with: urlRequest) { data, response, error in
                
                    // ensure there is no error for this HTTP response
                    let errorResponse = CosyncJWTError.checkResponse(data: data, response: response, error: error)
                    guard errorResponse == nil  else {
                        completion(errorResponse)
                        return
                    }

                    // ensure there is data returned from this HTTP response
                    guard let content = data else {
                        completion(CosyncJWTError.internalServerError)
                        return
                    }
                    
                    let str = String(decoding: content, as: UTF8.self)
                    
                    if str == "true" {
                        completion(nil)
                    } else {
                        completion(CosyncJWTError.internalServerError)
                    }

                }
                
                // execute the HTTP request
                task.resume()
                
            } else {
                completion(CosyncJWTError.invalidPassword)
            }

        } else {
            completion(CosyncJWTError.cosyncJWTConfiguration)
        }
        

    }
    
    // Change password into CosyncJWT
    public func changePassword(_ newPassword: String, password: String, onCompletion completion: @escaping (Error?) -> Void) {
        
        if  let cosyncRestAddress = self.cosyncRestAddress {
            
            if self.checkPassword(password) {
                
                let restPath = cosyncRestAddress
                
                if let accessToken = self.accessToken {
                    let config = URLSessionConfiguration.default

                    let session = URLSession(configuration: config)
                    
                    let url = URL(string: "\(restPath)/\(CosyncJWTRest.changePasswordPath)")!
                    var urlRequest = URLRequest(url: url)
                    urlRequest.httpMethod = "POST"
                    urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

                    // your post request data
                    var requestBodyComponents = URLComponents()
                    
                    requestBodyComponents.queryItems = [URLQueryItem(name: "newPassword", value: newPassword.md5()),
                                                        URLQueryItem(name: "password", value: password.md5())]

                    urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

                    let task = session.dataTask(with: urlRequest) { data, response, error in
                    
                        // ensure there is no error for this HTTP response
                        let errorResponse = CosyncJWTError.checkResponse(data: data, response: response, error: error)
                        guard errorResponse == nil  else {
                            completion(errorResponse)
                            return
                        }

                        // ensure there is data returned from this HTTP response
                        guard let content = data else {
                            completion(CosyncJWTError.internalServerError)
                            return
                        }
                        
                        let str = String(decoding: content, as: UTF8.self)
                        
                        if str == "true" {
                            completion(nil)
                        } else {
                            completion(CosyncJWTError.internalServerError)
                        }

                    }
                    
                    // execute the HTTP request
                    task.resume()
                }
                
            } else {
                completion(CosyncJWTError.invalidPassword)
            }
            
        } else {
            completion(CosyncJWTError.cosyncJWTConfiguration)
        }
        

    }
    
    // Get application data from CosyncJWT
    public func getApplication(onCompletion completion: @escaping (Error?) -> Void) {
        
        if  let appToken = self.appToken,
            let cosyncRestAddress = self.cosyncRestAddress {
            
            let restPath = cosyncRestAddress
            let appToken = appToken

            let config = URLSessionConfiguration.default
            config.httpAdditionalHeaders = ["app-token": appToken]

            let session = URLSession(configuration: config)
            
            let url = URL(string: "\(restPath)/\(CosyncJWTRest.getApplicationPath)")!
            
            let urlRequest = URLRequest(url: url)
            
            let task = session.dataTask(with: urlRequest) { data, response, error in
            
                // ensure there is no error for this HTTP response
                let errorResponse = CosyncJWTError.checkResponse(data: data, response: response, error: error)
                guard errorResponse == nil  else {
                    completion(errorResponse)
                    return
                }

                // ensure there is data returned from this HTTP response
                guard let content = data else {
                    completion(CosyncJWTError.internalServerError)
                    return
                }
                
                // serialise the data / NSData object into Dictionary [String : Any]
                guard let json = (try? JSONSerialization.jsonObject(with: content, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                    completion(CosyncJWTError.internalServerError)
                    return
                }
                
                if let name = json["name"] as? String {
                    self.appName = name
                }
                
                if let twoFactorVerification = json["twoFactorVerification"] as? String {
                    self.twoFactorVerification = twoFactorVerification
                }
                if let passwordFilter = json["passwordFilter"] as? Bool {
                    self.passwordFilter = passwordFilter
                }
                if let passwordMinLength = json["passwordMinLength"] as? Int {
                    self.passwordMinLength = passwordMinLength
                }
                if let passwordMinUpper = json["passwordMinUpper"] as? Int {
                    self.passwordMinUpper = passwordMinUpper
                }
                if let passwordMinLower = json["passwordMinLower"] as? Int {
                    self.passwordMinLower = passwordMinLower
                }
                if let passwordMinDigit = json["passwordMinDigit"] as? Int {
                     self.passwordMinDigit = passwordMinDigit
                }
                if let passwordMinSpecial = json["passwordMinSpecial"] as? Int {
                     self.passwordMinSpecial = passwordMinSpecial
                }

                if let appData = json["appData"] as? [String: Any] {
                    self.appData = appData
                }
                
                completion(nil)

            }
            
            // execute the HTTP request
            task.resume()
                

            
        } else {
            completion(CosyncJWTError.cosyncJWTConfiguration)
        }
        

    }
 
    // Invite into CosyncJWT
    public func invite(_ handle: String, metaData: String?, senderUserId: String?, onCompletion completion: @escaping (Error?) -> Void) {

        if  let cosyncRestAddress = self.cosyncRestAddress {
            
            let restPath = cosyncRestAddress
            if let accessToken = self.accessToken,
               let senderUserId = senderUserId {
                
                let config = URLSessionConfiguration.default
                let session = URLSession(configuration: config)
                
                let url = URL(string: "\(restPath)/\(CosyncJWTRest.invitePath)")!
                var urlRequest = URLRequest(url: url)
                urlRequest.httpMethod = "POST"
                urlRequest.allHTTPHeaderFields = ["access-token": accessToken]

                // your post request data
                var requestBodyComponents = URLComponents()
                if let metaData = metaData {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                        URLQueryItem(name: "metaData", value: metaData),
                                                        URLQueryItem(name: "senderUserId", value: senderUserId)]

                } else {
                    requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                        URLQueryItem(name: "senderUserId", value: senderUserId)]
                }
                
                urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

                let task = session.dataTask(with: urlRequest) { data, response, error in
                
                    // ensure there is no error for this HTTP response
                    let errorResponse = CosyncJWTError.checkResponse(data: data, response: response, error: error)
                    guard errorResponse == nil  else {
                        completion(errorResponse)
                        return
                    }

                    // ensure there is data returned from this HTTP response
                    guard let content = data else {
                        completion(CosyncJWTError.internalServerError)
                        return
                    }
                    
                    let str = String(decoding: content, as: UTF8.self)
                    
                    if str == "true" {
                        completion(nil)
                    } else {
                        completion(CosyncJWTError.internalServerError)
                    }

                }
                
                // execute the HTTP request
                task.resume()
            }
        } else {
            completion(CosyncJWTError.cosyncJWTConfiguration)
        }

    }
    
    // register into CosyncJWT
    public func register(_ handle: String, password: String, metaData: String?, code: String, onCompletion completion: @escaping (Error?) -> Void) {
        
        if  let appToken = self.appToken,
            let cosyncRestAddress = self.cosyncRestAddress {
            
            CosyncJWTRest.shared.getApplication(onCompletion: { (err) in
                
                if let error = err {
                    completion(error)
                } else {
                    
                    if self.checkPassword(password) {

                        let restPath = cosyncRestAddress
                        let appToken = appToken
                        
                        let config = URLSessionConfiguration.default

                        let session = URLSession(configuration: config)
                        
                        let url = URL(string: "\(restPath)/\(CosyncJWTRest.registerPath)")!
                        var urlRequest = URLRequest(url: url)
                        urlRequest.httpMethod = "POST"
                        urlRequest.allHTTPHeaderFields = ["app-token": appToken]

                        // your post request data
                        var requestBodyComponents = URLComponents()
                        
                        if let metaData = metaData {
                            requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                                URLQueryItem(name: "password", value: password.md5()),
                                                                URLQueryItem(name: "code", value: code),
                                                                URLQueryItem(name: "metaData", value: metaData)]

                        } else {
                            requestBodyComponents.queryItems = [URLQueryItem(name: "handle", value: handle),
                                                                URLQueryItem(name: "password", value: password.md5()),
                                                                URLQueryItem(name: "code", value: code)]
                        }
                        
                        urlRequest.httpBody = requestBodyComponents.query?.data(using: .utf8)

                        let task = session.dataTask(with: urlRequest) { data, response, error in
                        
                            // ensure there is no error for this HTTP response
                            let errorResponse = CosyncJWTError.checkResponse(data: data, response: response, error: error)
                            guard errorResponse == nil  else {
                                completion(errorResponse)
                                return
                            }

                            // ensure there is data returned from this HTTP response
                            guard let content = data else {
                                completion(CosyncJWTError.internalServerError)
                                return
                            }
                            
                            // serialise the data / NSData object into Dictionary [String : Any]
                            guard let json = (try? JSONSerialization.jsonObject(with: content, options: JSONSerialization.ReadingOptions.mutableContainers)) as? [String: Any] else {
                                completion(CosyncJWTError.internalServerError)
                                return
                            }
                            
                            if let jwt = json["jwt"] as? String,
                               let accessToken = json["access-token"] as? String,
                               let signedUserToken = json["signed-user-token"] as? String {
                                
                                self.jwt = jwt
                                self.accessToken = accessToken
                                self.signedUserToken = signedUserToken

                                completion(nil)
                            } else {
                                completion(CosyncJWTError.internalServerError)
                            }

                        }
                        
                        // execute the HTTP request
                        task.resume()
                        
                        
                    } else {
                        completion(CosyncJWTError.invalidPassword)
                    }
                }
            })

        } else {
            completion(CosyncJWTError.cosyncJWTConfiguration)
        }
        
        
    }
    
    public func logout() {
        self.jwt = nil
        self.accessToken = nil
        self.handle = nil
        self.metaData = nil
        self.lastLogin = nil
    }

}
