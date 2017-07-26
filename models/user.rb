class User < ActiveRecord::Base
  validates_uniqueness_of :user_name, :email
end
