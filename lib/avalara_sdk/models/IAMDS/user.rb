=begin
#foundation

#Platform foundation consists of services on top of which the Avalara Compliance Cloud platform is built. These services are foundational and provide functionality such as common organization, tenant and user management for the rest of the compliance platform.

SDK Version : 2.4.34


=end

require 'date'
require 'time'

module AvalaraSdk::IAMDS
  # Representation of an User
  class User
    # Identifier for the user in external systems (clients). The external systems manage this
    attr_accessor :external_id

    # Human readable unique identifier of the user, typically used to authenticate with an identity provider
    attr_accessor :user_name

    attr_accessor :organization

    # The components of the user's real name.  Providers MAY return just the full name as a single string in the formatted sub-attribute, or they MAY return just the individual component attributes using the other sub-attributes, or they MAY return both.  If both variants are returned, they SHOULD be describing the same name, with the formatted name indicating how the component attributes should be combined.
    attr_accessor :name

    # The name of the User, suitable for display to end-users.  The name SHOULD be the full name of the User being described, if known
    attr_accessor :display_name

    # The casual way to address the user in real life, e.g., 'Bob' or 'Bobby' instead of 'Robert'.  This attribute SHOULD NOT be used to represent a User's username (e.g., 'bjensen' or 'mpepperidge')
    attr_accessor :nick_name

    # A fully qualified URL pointing to a page representing the User's online profile
    attr_accessor :profile_url

    # The user's title, such as \"Vice President.\"
    attr_accessor :title

    # Used to identify the relationship between the organization and the user.  Typical values used might be 'Contractor', 'Employee', 'Intern', 'Temp', 'External', and 'Unknown', but any value may be used
    attr_accessor :user_type

    # Indicates the User's preferred written or spoken language.  Generally used for selecting a localized user interface; e.g., 'en_US' specifies the language English and country US
    attr_accessor :preferred_language

    # Used to indicate the User's default location for purposes of localizing items such as currency, date time format, or numerical representations
    attr_accessor :locale

    # The User's time zone in the 'Olson' time zone database format, e.g., 'America/Los_Angeles'
    attr_accessor :timezone

    # A Boolean value indicating the User's administrative status
    attr_accessor :active

    # The User's cleartext password.  This attribute is intended to be used as a means to specify an initial password when creating a new User or to reset an existing User's password
    attr_accessor :password

    # A List of email addresses associated with the user
    attr_accessor :emails

    # A List of phone numbers associated with the user
    attr_accessor :phone_numbers

    # A physical mailing address for this User, as described in (address Element). Canonical Type Values of work, home, and other. The value attribute is a complex type with the following sub-attributes
    attr_accessor :addresses

    attr_accessor :default_tenant

    # Custom claims that are returned along with a requested scope during authentication
    attr_accessor :custom_claims

    # Unique identifier for the Object
    attr_accessor :id

    attr_accessor :meta

    # Identifier of the Resource (if any) in other systems
    attr_accessor :aspects

    # User defined tags in the form of key:value pair
    attr_accessor :tags

    # Attribute mapping from ruby-style variable name to JSON key.
    def self.attribute_map
      {
        :'external_id' => :'externalId',
        :'user_name' => :'userName',
        :'organization' => :'organization',
        :'name' => :'name',
        :'display_name' => :'displayName',
        :'nick_name' => :'nickName',
        :'profile_url' => :'profileUrl',
        :'title' => :'title',
        :'user_type' => :'userType',
        :'preferred_language' => :'preferredLanguage',
        :'locale' => :'locale',
        :'timezone' => :'timezone',
        :'active' => :'active',
        :'password' => :'password',
        :'emails' => :'emails',
        :'phone_numbers' => :'phoneNumbers',
        :'addresses' => :'addresses',
        :'default_tenant' => :'defaultTenant',
        :'custom_claims' => :'customClaims',
        :'id' => :'id',
        :'meta' => :'meta',
        :'aspects' => :'aspects',
        :'tags' => :'tags'
      }
    end

    # Returns all the JSON keys this model knows about
    def self.acceptable_attributes
      attribute_map.values
    end

    # Attribute type mapping.
    def self.openapi_types
      {
        :'external_id' => :'String',
        :'user_name' => :'String',
        :'organization' => :'Reference',
        :'name' => :'Object',
        :'display_name' => :'String',
        :'nick_name' => :'String',
        :'profile_url' => :'String',
        :'title' => :'String',
        :'user_type' => :'String',
        :'preferred_language' => :'String',
        :'locale' => :'String',
        :'timezone' => :'String',
        :'active' => :'Boolean',
        :'password' => :'String',
        :'emails' => :'Array<Object>',
        :'phone_numbers' => :'Array<Object>',
        :'addresses' => :'Array<Object>',
        :'default_tenant' => :'Reference',
        :'custom_claims' => :'Array<Object>',
        :'id' => :'String',
        :'meta' => :'InstanceMeta',
        :'aspects' => :'Array<Aspect>',
        :'tags' => :'Array<Tag>'
      }
    end

    # List of attributes with nullable: true
    def self.openapi_nullable
      Set.new([
      ])
    end

    # List of class defined in allOf (OpenAPI v3)
    def self.openapi_all_of
      [
      :'Instance'
      ]
    end

    # Initializes the object
    # @param [Hash] attributes Model attributes in the form of hash
    def initialize(attributes = {})
      if (!attributes.is_a?(Hash))
        fail ArgumentError, "The input argument (attributes) must be a hash in `AvalaraSdk::IAMDS::User` initialize method"
      end

      # check to see if the attribute exists and convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h|
        if (!self.class.attribute_map.key?(k.to_sym))
          fail ArgumentError, "`#{k}` is not a valid attribute in `AvalaraSdk::IAMDS::User`. Please check the name to make sure it's valid. List of attributes: " + self.class.attribute_map.keys.inspect
        end
        h[k.to_sym] = v
      }

      if attributes.key?(:'external_id')
        self.external_id = attributes[:'external_id']
      end

      if attributes.key?(:'user_name')
        self.user_name = attributes[:'user_name']
      end

      if attributes.key?(:'organization')
        self.organization = attributes[:'organization']
      end

      if attributes.key?(:'name')
        if (value = attributes[:'name']).is_a?(Hash)
          self.name = value
        end
        self.name = attributes[:'name']
      end

      if attributes.key?(:'display_name')
        self.display_name = attributes[:'display_name']
      end

      if attributes.key?(:'nick_name')
        self.nick_name = attributes[:'nick_name']
      end

      if attributes.key?(:'profile_url')
        self.profile_url = attributes[:'profile_url']
      end

      if attributes.key?(:'title')
        self.title = attributes[:'title']
      end

      if attributes.key?(:'user_type')
        self.user_type = attributes[:'user_type']
      end

      if attributes.key?(:'preferred_language')
        self.preferred_language = attributes[:'preferred_language']
      end

      if attributes.key?(:'locale')
        self.locale = attributes[:'locale']
      end

      if attributes.key?(:'timezone')
        self.timezone = attributes[:'timezone']
      end

      if attributes.key?(:'active')
        self.active = attributes[:'active']
      end

      if attributes.key?(:'password')
        self.password = attributes[:'password']
      end

      if attributes.key?(:'emails')
        if (value = attributes[:'emails']).is_a?(Array)
          self.emails = value
        end
      end

      if attributes.key?(:'phone_numbers')
        if (value = attributes[:'phone_numbers']).is_a?(Array)
          self.phone_numbers = value
        end
      end

      if attributes.key?(:'addresses')
        if (value = attributes[:'addresses']).is_a?(Array)
          self.addresses = value
        end
      end

      if attributes.key?(:'default_tenant')
        self.default_tenant = attributes[:'default_tenant']
      end

      if attributes.key?(:'custom_claims')
        if (value = attributes[:'custom_claims']).is_a?(Array)
          self.custom_claims = value
        end
      end

      if attributes.key?(:'id')
        self.id = attributes[:'id']
      end

      if attributes.key?(:'meta')
        self.meta = attributes[:'meta']
      end

      if attributes.key?(:'aspects')
        if (value = attributes[:'aspects']).is_a?(Array)
          self.aspects = value
        end
      end

      if attributes.key?(:'tags')
        if (value = attributes[:'tags']).is_a?(Array)
          self.tags = value
        end
      end
    end

    # Show invalid properties with the reasons. Usually used together with valid?
    # @return Array for valid properties with the reasons
    def list_invalid_properties
      invalid_properties = Array.new
      if @user_name.nil?
        invalid_properties.push('invalid value for "user_name", user_name cannot be nil.')
      end

      if @organization.nil?
        invalid_properties.push('invalid value for "organization", organization cannot be nil.')
      end

      if @emails.nil?
        invalid_properties.push('invalid value for "emails", emails cannot be nil.')
      end

      if @emails.length < 1
        invalid_properties.push('invalid value for "emails", number of items must be greater than or equal to 1.')
      end

      if @id.nil?
        invalid_properties.push('invalid value for "id", id cannot be nil.')
      end

      invalid_properties
    end

    # Check to see if the all the properties in the model are valid
    # @return true if the model is valid
    def valid?
      return false if @user_name.nil?
      return false if @organization.nil?
      return false if @emails.nil?
      return false if @emails.length < 1
      return false if @id.nil?
      true
    end

    # Custom attribute writer method with validation
    # @param [Object] emails Value to be assigned
    def emails=(emails)
      if emails.nil?
        fail ArgumentError, 'emails cannot be nil'
      end

      if emails.length < 1
        fail ArgumentError, 'invalid value for "emails", number of items must be greater than or equal to 1.'
      end

      @emails = emails
    end

    # Checks equality by comparing each attribute.
    # @param [Object] Object to be compared
    def ==(o)
      return true if self.equal?(o)
      self.class == o.class &&
          external_id == o.external_id &&
          user_name == o.user_name &&
          organization == o.organization &&
          name == o.name &&
          display_name == o.display_name &&
          nick_name == o.nick_name &&
          profile_url == o.profile_url &&
          title == o.title &&
          user_type == o.user_type &&
          preferred_language == o.preferred_language &&
          locale == o.locale &&
          timezone == o.timezone &&
          active == o.active &&
          password == o.password &&
          emails == o.emails &&
          phone_numbers == o.phone_numbers &&
          addresses == o.addresses &&
          default_tenant == o.default_tenant &&
          custom_claims == o.custom_claims &&
          id == o.id &&
          meta == o.meta &&
          aspects == o.aspects &&
          tags == o.tags
    end

    # @see the `==` method
    # @param [Object] Object to be compared
    def eql?(o)
      self == o
    end

    # Calculates hash code according to all attributes.
    # @return [Integer] Hash code
    def hash
      [external_id, user_name, organization, name, display_name, nick_name, profile_url, title, user_type, preferred_language, locale, timezone, active, password, emails, phone_numbers, addresses, default_tenant, custom_claims, id, meta, aspects, tags].hash
    end

    # Builds the object from hash
    # @param [Hash] attributes Model attributes in the form of hash
    # @return [Object] Returns the model itself
    def self.build_from_hash(attributes)
      new.build_from_hash(attributes)
    end

    # Builds the object from hash
    # @param [Hash] attributes Model attributes in the form of hash
    # @return [Object] Returns the model itself
    def build_from_hash(attributes)
      return nil unless attributes.is_a?(Hash)
      self.class.openapi_types.each_pair do |key, type|
        if attributes[self.class.attribute_map[key]].nil? && self.class.openapi_nullable.include?(key)
          self.send("#{key}=", nil)
        elsif type =~ /\AArray<(.*)>/i
          # check to ensure the input is an array given that the attribute
          # is documented as an array but the input is not
          if attributes[self.class.attribute_map[key]].is_a?(Array)
            self.send("#{key}=", attributes[self.class.attribute_map[key]].map { |v| _deserialize($1, v) })
          end
        elsif !attributes[self.class.attribute_map[key]].nil?
          self.send("#{key}=", _deserialize(type, attributes[self.class.attribute_map[key]]))
        end
      end

      self
    end

    # Deserializes the data based on type
    # @param string type Data type
    # @param string value Value to be deserialized
    # @return [Object] Deserialized data
    def _deserialize(type, value)
      case type.to_sym
      when :Time
        Time.parse(value)
      when :Date
        Date.parse(value)
      when :String
        value.to_s
      when :Integer
        value.to_i
      when :Float
        value.to_f
      when :Boolean
        if value.to_s =~ /\A(true|t|yes|y|1)\z/i
          true
        else
          false
        end
      when :Object
        # generic object (usually a Hash), return directly
        value
      when /\AArray<(?<inner_type>.+)>\z/
        inner_type = Regexp.last_match[:inner_type]
        value.map { |v| _deserialize(inner_type, v) }
      when /\AHash<(?<k_type>.+?), (?<v_type>.+)>\z/
        k_type = Regexp.last_match[:k_type]
        v_type = Regexp.last_match[:v_type]
        {}.tap do |hash|
          value.each do |k, v|
            hash[_deserialize(k_type, k)] = _deserialize(v_type, v)
          end
        end
      else # model
        # models (e.g. Pet) or oneOf
        klass = AvalaraSdk::IAMDS.const_get(type)
        klass.respond_to?(:openapi_one_of) ? klass.build(value) : klass.build_from_hash(value)
      end
    end

    # Returns the string representation of the object
    # @return [String] String presentation of the object
    def to_s
      to_hash.to_s
    end

    # to_body is an alias to to_hash (backward compatibility)
    # @return [Hash] Returns the object in the form of hash
    def to_body
      to_hash
    end

    # Returns the object in the form of hash
    # @return [Hash] Returns the object in the form of hash
    def to_hash
      hash = {}
      self.class.attribute_map.each_pair do |attr, param|
        value = self.send(attr)
        if value.nil?
          is_nullable = self.class.openapi_nullable.include?(attr)
          next if !is_nullable || (is_nullable && !instance_variable_defined?(:"@#{attr}"))
        end

        hash[param] = _to_hash(value)
      end
      hash
    end

    # Outputs non-array value in the form of hash
    # For object, use to_hash. Otherwise, just return the value
    # @param [Object] value Any valid value
    # @return [Hash] Returns the value in the form of hash
    def _to_hash(value)
      if value.is_a?(Array)
        value.compact.map { |v| _to_hash(v) }
      elsif value.is_a?(Hash)
        {}.tap do |hash|
          value.each { |k, v| hash[k] = _to_hash(v) }
        end
      elsif value.respond_to? :to_hash
        value.to_hash
      else
        value
      end
    end

  end

end
