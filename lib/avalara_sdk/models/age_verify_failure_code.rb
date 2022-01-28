=begin
#Avalara Shipping Verification only

#API for evaluating transactions against direct-to-consumer Beverage Alcohol shipping regulations.  This API is currently in beta. 

SDK Version : 2.3.3


=end

require 'date'
require 'time'

module AvalaraSdk
  class AgeVerifyFailureCode
    NOT_FOUND = "not_found".freeze
    DOB_UNVERIFIABLE = "dob_unverifiable".freeze
    UNDER_AGE = "under_age".freeze
    SUSPECTED_FRAUD = "suspected_fraud".freeze
    DECEASED = "deceased".freeze
    UNKNOWN_ERROR = "unknown_error".freeze

    # Builds the enum from string
    # @param [String] The enum value in the form of the string
    # @return [String] The enum value
    def self.build_from_hash(value)
      new.build_from_hash(value)
    end

    # Builds the enum from string
    # @param [String] The enum value in the form of the string
    # @return [String] The enum value
    def build_from_hash(value)
      constantValues = AgeVerifyFailureCode.constants.select { |c| AgeVerifyFailureCode::const_get(c) == value }
      raise "Invalid ENUM value #{value} for class #AgeVerifyFailureCode" if constantValues.empty?
      value
    end
  end
end
