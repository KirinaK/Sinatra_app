require 'sinatra'
require 'rest-client'
require 'json'
require 'pry'
require 'dotenv/load'
require 'active_record'
require 'jwt'
require './models/user.rb'

CLIENT_ID = ENV['CLIENT_ID']
CLIENT_SECRET = ENV['CLIENT_SECRET']
GITHUB_USER_URL = 'https://api.github.com/user'
GITHUB_ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_AUTHORIZE_URL="https://github.com/login/oauth/authorize?scope=user:email&client_id="

use Rack::Session::Pool, cookie_only: false

def determine_access_token
  session[:access_token]
end

def authenticate!
  erb :index, locals: { client_id: CLIENT_ID }
end

get '/' do
  if access_token = determine_access_token
    scopes = []

    begin
      auth_result = RestClient.get(GITHUB_USER_URL, 
                                   { params: { access_token: access_token }, accept: :json })
      login = JSON.parse(auth_result)['login']
      session[:current_user_id] = JWT.encode(login, CLIENT_SECRET)
    rescue => e
      session[:access_token] = nil
      return authenticate!
    end

    if auth_result.headers.include? :x_oauth_scopes
      scopes = auth_result.headers[:x_oauth_scopes].split(', ')
    end

    auth_result = JSON.parse(auth_result)

    if scopes.include? 'user:email'
      emails = RestClient.get("#{GITHUB_USER_URL}/emails",
                              { params: { access_token: access_token }, accept: :json })
      auth_result['private_emails'] = JSON.parse(emails)
    end

    email = auth_result['email'] || auth_result['private_emails'][0]['email']

    User.create(user_name: auth_result['login'], email: email)
    auth_result[:current_user_id] = JWT.decode(session[:current_user_id], CLIENT_SECRET)[0]
    erb :advanced, locals: auth_result
  else
    authenticate!
  end
end

get '/authorize' do
  redirect GITHUB_AUTHORIZE_URL + CLIENT_ID
end

get '/callback' do
  session_code = request.env['rack.request.query_hash']['code']
  result = RestClient.post(GITHUB_ACCESS_TOKEN_URL,
                           {
                             client_id: CLIENT_ID,
                             client_secret: CLIENT_SECRET,
                             code: session_code
                           },
                           accept: :json)
  session[:access_token] = JSON.parse(result)['access_token']
  redirect '/'
end

get '/show_users' do
  @users = User.all
  erb :show_users
end

get '/logout' do
  session[:access_token] = session[:jwt_token] = nil
  redirect '/'
end
