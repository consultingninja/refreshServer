import type { RequestEvent } from './$types';
import jwt from 'jsonwebtoken';
import {SECRET_ACCESS,SECRET_COMM,SECRET_REFRESH} from '$env/static/private';




export const POST  = async({cookies}:RequestEvent)=>{
    const commToken = cookies.get('commToken');

    
        if(!commToken)
        return new Response(JSON.stringify({error: true,success:false,message: "Invalid Request!", data: undefined}),{status: 401});



        try{
            const claims = jwt.verify(commToken,SECRET_COMM);
            if(!claims){
                return new Response(JSON.stringify({error: true,success:false,message: "Unauthorized!", data: undefined}),{status: 401});
            }
    
            if(claims){
                //only if the comm token checks out do we check refresh token
                try{
                    const refreshToken = cookies.get("refreshToken");

                    if(!refreshToken)return new Response(JSON.stringify({error: true,success:false,message: "Invalid Request!", data: undefined}),{status: 401});
    
                    const refreshClaims = jwt.verify(commToken,SECRET_REFRESH);
    
                    if(!refreshClaims){
                        return new Response(JSON.stringify({error: true,success:false,message: "Unauthorized!", data: undefined}),{status: 401});
                    }
    
                    const newAccessToken = jwt.sign({authedUser:claims.authedUser},SECRET_ACCESS,{expiresIn:'10m'});
                    cookies.set('authToken',newAccessToken,{httpOnly: true,maxAge:60 * 60 * 24,sameSite: 'strict'});
        
                    return new Response(JSON.stringify({error: false,success:true,message: "Success", data: undefined}),{status: 200});
                }
                catch(error){
                    if (error.name === 'TokenExpiredError') {
                        return new Response(JSON.stringify({error: true,success:false,message: "Refresh Expired", data: undefined}),{status: 401});
                        }
                        if (error.name === 'JsonWebTokenError') {
                            return new Response(JSON.stringify({error: true,success:false,message: "Unable to verify comms!", data: undefined}),{status: 500});
                        }
                        if (error.name === 'NotBeforeError') {
                            return new Response(JSON.stringify({error: true,success:false,message: "Invalid comm status", data: undefined}),{status: 401});
                        }
                        if (error.name === 'JsonWebTokenError') {
                            return new Response(JSON.stringify({error: true,success:false,message: "Invalid comm status", data: undefined}),{status: 401});
                        }
                }

            }
        }
        catch(error){
            if (error.name === 'TokenExpiredError') {
                return new Response(JSON.stringify({error: true,success:false,message: "Comms Expired, try again!", data: undefined}),{status: 401});
                }
                if (error.name === 'JsonWebTokenError') {
                    return new Response(JSON.stringify({error: true,success:false,message: "Unable to verify comms!", data: undefined}),{status: 500});
                }
                if (error.name === 'NotBeforeError') {
                    return new Response(JSON.stringify({error: true,success:false,message: "Invalid comm status", data: undefined}),{status: 401});
                }
                if (error.name === 'JsonWebTokenError') {
                    return new Response(JSON.stringify({error: true,success:false,message: "Invalid comm status", data: undefined}),{status: 401});
                }
        }

    return new Response(JSON.stringify({error: true,success:false,message: "Unknown error", data: undefined}),{status: 500});

}