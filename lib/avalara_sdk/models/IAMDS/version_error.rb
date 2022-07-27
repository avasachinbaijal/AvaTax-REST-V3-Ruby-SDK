=begin
#foundation

#Platform foundation consists of services on top of which the Avalara Compliance Cloud platform is built. These services are foundational and provide functionality such as common organization, tenant and user management for the rest of the compliance platform.

SDK Version : 2.4.41


=end

require 'date'
require 'time'

module AvalaraSdk::IAMDS
  class VersionError
    TOO_NEW = "version-too-new".freeze
    TOO_OLD = "version-too-old".freeze
    NOT_VALID = "version-not-valid".freeze

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
      constantValues = VersionError.constants.select { |c| VersionError::const_get(c) == value }
      raise "Invalid ENUM value #{value} for class #VersionError" if constantValues.empty?
      value
    end
  end
end
