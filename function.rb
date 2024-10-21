# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  path = event['path']
  case path
  when '/auth/token'
    authenticate(req: event)
  when '/'
    get(req: event)
  else
    response(body: nil, status: 404)
  end
end

def authenticate(req:)
  method = req["httpMethod"]
  headers = req["headers"].transform_keys{ |key| key.to_s.downcase }
  body = req["body"]

  if(method != "POST")
    return response(body:nil, status: 405)
  end
  if(headers['content-type'] != "application/json")
    return response(body: nil, status: 415)
  end
  if(!isValidJson(json: body))
    return response(body: nil, status: 422)
  end

  ENV['JWT_SECRET'] = 'SOMESECRET'
  payload = {
      data: JSON.parse(body),
      exp: Time.now.to_i + 5,
      nbf: Time.now.to_i + 2
    }
  token= JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  return response(body: {"token": token}, status: 201)
end

def get(req:)
  method = req["httpMethod"]
  headers = req["headers"].transform_keys{ |key| key.to_s.downcase }
  body = req["body"]

  if(method != "GET")
    return response(body:nil, status: 405)
  end
  
  token = bearer_token(auth: (headers['authorization']).to_s.strip)
  if(token)
    ENV['JWT_SECRET'] = 'SOMESECRET'
    begin
      decoded = JWT.decode(token, ENV['JWT_SECRET'], true, {algorithm: 'HS256'})
      return response(body: decoded[0]["data"], status: 200)
    rescue JWT::ExpiredSignature, JWT::ImmatureSignature => e
      return response(body:nil, status: 401)
    rescue JWT::DecodeError, StandardError => e
      return response(body:nil, status: 403)
    end
  else 
    return response(body:nil, status: 403)
  end
end

def isValidJson(json:)
  JSON.parse(json)
rescue JSON::ParserError, TypeError => e
  false
end

def bearer_token(auth:)
  pattern = /^Bearer /
  auth.gsub(pattern, '') if auth && auth.match(pattern)
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'SOMESECRET'

  # Call /auth/token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/auth/token'
             })
  # case insensitive content type
  PP.pp main(context: {}, event: {
              'body' => '{"name": "bboe"}',
              'headers' => { 'Content-tYpe' => 'application/json' },
              'httpMethod' => 'POST',
              'path' => '/auth/token'
            })
  # invalid json
  PP.pp main(context: {}, event: {
              'body' => '"name": "bboe"}',
              'headers' => { 'Content-Type' => 'application/json' },
              'httpMethod' => 'POST',
              'path' => '/auth/token'
            })
  # invalid method
  PP.pp main(context: {}, event: {
              'body' => '{"name": "bboe"}',
              'headers' => { 'Content-Type' => 'application/json' },
              'httpMethod' => 'GET',
              'path' => '/auth/token'
            })
  # invalid header
  PP.pp main(context: {}, event: {
              'body' => '{"name": "bboe"}',
              'headers' => { 'Content-Type' => 'application/text' },
              'httpMethod' => 'POST',
              'path' => '/auth/token'
            })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  payload2 = {
    data: { user_id: 128 },
    exp: Time.now.to_i,
    nbf: Time.now.to_i
  }
  token2 = JWT.encode payload2, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
             PP.pp main(context: {}, event: {
              'headers' => { 'Authorization' => "Bearer eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7Im5hbWUiOiJiYm9lIn0sImV4cCI6MTcyOTQ3OTY4NywibmJmIjoxNzI5NDc5MTg5fQ.brfNqwGkhQGSagQehLBsb0iMexpzvv-R-qH2Rb1CCw0",
                             'Content-Type' => 'application/json' },
              'httpMethod' => 'GET',
              'path' => '/'
            })
  # invalid Authorization key
  PP.pp main(context: {}, event: {
    'headers' => { 'Auth' => "Bearer #{token}",
                   'Content-Type' => 'application/json' },
    'httpMethod' => 'GET',
    'path' => '/'
  })
  # invalid Authorization value
  PP.pp main(context: {}, event: {
    'headers' => { 'Authorization' => "#{token}",
                   'Content-Type' => 'application/json' },
    'httpMethod' => 'GET',
    'path' => '/'
  })
  # expired token
  PP.pp main(context: {}, event: {
              'headers' => { 'Authorization' => "Bearer #{token2}",
                             'Content-Type' => 'application/json' },
              'httpMethod' => 'GET',
              'path' => '/'
            })
  # invalid token
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer ghuih.biu.nbiujh",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
  

  # Call something else
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/hey'
             })
end
