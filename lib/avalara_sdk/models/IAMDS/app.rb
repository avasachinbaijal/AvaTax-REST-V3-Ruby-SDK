=begin
#foundation

#Platform foundation consists of services on top of which the Avalara Compliance Cloud platform is built. These services are foundational and provide functionality such as common organization, tenant and user management for the rest of the compliance platform.

SDK Version : 2.4.41


=end

require 'date'
require 'time'

module AvalaraSdk::IAMDS
  # An App represents any software package that intends to interact with Avalara Compliance Cloud
  class App
    # Name of the App/Service
    attr_accessor :display_name

    # Type of application
    attr_accessor :type

    attr_accessor :organization

    # Whether the App is allowed to access information across all Tenants within its Organization
    attr_accessor :is_tenant_agnostic

    # Whether the App is allowed to access information across all Organizations and Tenants
    attr_accessor :is_org_agnostic

    attr_accessor :tenants

    # The clientId used for OAuth flows
    attr_accessor :client_id

    # Defines the registered redirect URIs for the app - determines where tokens are sent after authentication
    attr_accessor :redirect_uris

    # List of grants associated with the App
    attr_accessor :grants

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
        :'display_name' => :'displayName',
        :'type' => :'type',
        :'organization' => :'organization',
        :'is_tenant_agnostic' => :'isTenantAgnostic',
        :'is_org_agnostic' => :'isOrgAgnostic',
        :'tenants' => :'tenants',
        :'client_id' => :'clientId',
        :'redirect_uris' => :'redirectUris',
        :'grants' => :'grants',
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
        :'display_name' => :'String',
        :'type' => :'String',
        :'organization' => :'Reference',
        :'is_tenant_agnostic' => :'Boolean',
        :'is_org_agnostic' => :'Boolean',
        :'tenants' => :'Array<Object>',
        :'client_id' => :'String',
        :'redirect_uris' => :'Array<String>',
        :'grants' => :'Array<Reference>',
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
        fail ArgumentError, "The input argument (attributes) must be a hash in `AvalaraSdk::IAMDS::App` initialize method"
      end

      # check to see if the attribute exists and convert string to symbol for hash key
      attributes = attributes.each_with_object({}) { |(k, v), h|
        if (!self.class.attribute_map.key?(k.to_sym))
          fail ArgumentError, "`#{k}` is not a valid attribute in `AvalaraSdk::IAMDS::App`. Please check the name to make sure it's valid. List of attributes: " + self.class.attribute_map.keys.inspect
        end
        h[k.to_sym] = v
      }

      if attributes.key?(:'display_name')
        self.display_name = attributes[:'display_name']
      end

      if attributes.key?(:'type')
        self.type = attributes[:'type']
      end

      if attributes.key?(:'organization')
        self.organization = attributes[:'organization']
      end

      if attributes.key?(:'is_tenant_agnostic')
        self.is_tenant_agnostic = attributes[:'is_tenant_agnostic']
      else
        self.is_tenant_agnostic = false
      end

      if attributes.key?(:'is_org_agnostic')
        self.is_org_agnostic = attributes[:'is_org_agnostic']
      else
        self.is_org_agnostic = false
      end

      if attributes.key?(:'tenants')
        if (value = attributes[:'tenants']).is_a?(Array)
          self.tenants = value
        end
      end

      if attributes.key?(:'client_id')
        self.client_id = attributes[:'client_id']
      end

      if attributes.key?(:'redirect_uris')
        if (value = attributes[:'redirect_uris']).is_a?(Array)
          self.redirect_uris = value
        end
      end

      if attributes.key?(:'grants')
        if (value = attributes[:'grants']).is_a?(Array)
          self.grants = value
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
      if @display_name.nil?
        invalid_properties.push('invalid value for "display_name", display_name cannot be nil.')
      end

      if @type.nil?
        invalid_properties.push('invalid value for "type", type cannot be nil.')
      end

      if @organization.nil?
        invalid_properties.push('invalid value for "organization", organization cannot be nil.')
      end

      if @id.nil?
        invalid_properties.push('invalid value for "id", id cannot be nil.')
      end

      invalid_properties
    end

    # Check to see if the all the properties in the model are valid
    # @return true if the model is valid
    def valid?
      return false if @display_name.nil?
      return false if @type.nil?
      type_validator = EnumAttributeValidator.new('String', ["spa", "web", "native"])
      return false unless type_validator.valid?(@type)
      return false if @organization.nil?
      return false if @id.nil?
      true
    end

    # Custom attribute writer method checking allowed values (enum).
    # @param [Object] type Object to be assigned
    def type=(type)
      validator = EnumAttributeValidator.new('String', ["spa", "web", "native"])
      unless validator.valid?(type)
        fail ArgumentError, "invalid value for \"type\", must be one of #{validator.allowable_values}."
      end
      @type = type
    end

    # Checks equality by comparing each attribute.
    # @param [Object] Object to be compared
    def ==(o)
      return true if self.equal?(o)
      self.class == o.class &&
          display_name == o.display_name &&
          type == o.type &&
          organization == o.organization &&
          is_tenant_agnostic == o.is_tenant_agnostic &&
          is_org_agnostic == o.is_org_agnostic &&
          tenants == o.tenants &&
          client_id == o.client_id &&
          redirect_uris == o.redirect_uris &&
          grants == o.grants &&
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
      [display_name, type, organization, is_tenant_agnostic, is_org_agnostic, tenants, client_id, redirect_uris, grants, id, meta, aspects, tags].hash
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
