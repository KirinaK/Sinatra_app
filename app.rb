require 'sinatra'
require 'rest-client'
require 'json'
require 'pry'
require 'dotenv/load'
require 'active_record'
require 'jwt'
require './models/user.rb'

ActiveRecord::Base.establish_connection(
  :adapter => 'postgresql',
  :database =>  'sinatra'
)

CLIENT_ID = ENV['CLIENT_ID']
CLIENT_SECRET = ENV['CLIENT_SECRET']

use Rack::Session::Pool, cookie_only: false

  def authenticated?
    session[:access_token]
  end

  def authenticate!
    erb :index, locals: { client_id: CLIENT_ID }
  end

  get '/' do
    if authenticated?
      access_token = session[:access_token]
      scopes = []

      begin
        auth_result = RestClient.get('https://api.github.com/user',
                                     { params: { access_token: access_token },
                                      accept: :json })
        session[:current_user_id] = JWT.encode(JSON.parse(auth_result)['login'], CLIENT_SECRET)
      rescue => e
        session[:access_token] = nil
        return authenticate!
      end

      if auth_result.headers.include? :x_oauth_scopes
        scopes = auth_result.headers[:x_oauth_scopes].split(', ')
      end

      auth_result = JSON.parse(auth_result)

      if scopes.include? 'user:email'
        auth_result['private_emails'] =
          JSON.parse(RestClient.get('https://api.github.com/user/emails',
                                    { params: { access_token: access_token },
                                    accept: :json }))
      end

      email = auth_result['email'] || auth_result['private_emails'][0]['email']

      User.create(user_name: auth_result['login'], email: email)
      auth_result[:current_user_id] = JWT.decode(session[:current_user_id], CLIENT_SECRET)[0]
      erb :advanced, locals: auth_result
    else
      authenticate!
    end
  end

  get '/callback' do
    session_code = request.env['rack.request.query_hash']['code']
    result = RestClient.post('https://github.com/login/oauth/access_token',
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
