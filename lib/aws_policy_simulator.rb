module AwsPolicySimulator

  # Based on
  # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html

  class RequestContext

    attr_reader :principal, :action, :resource, :environment

    def initialize(principal, action, resource, environment={})
      @principal = principal
      @action = action
      @resource = resource
      @environment = environment
    end

  end

  class Resource

    attr_reader :arn

    def initialize(arn)
      @arn = arn
    end

  end

  class PartialResult
    def allowed? ; false ; end
    def denied?  ; false ; end
  end

  ALLOWED = PartialResult.new
  DENIED  = PartialResult.new
  NEITHER = PartialResult.new

  def ALLOWED.allowed? ; true ; end
  def DENIED.denied?   ; true ; end

  def ALLOWED.inspect ; "ALLOWED" ; end
  def DENIED.inspect  ; "DENIED"  ; end
  def NEITHER.inspect ; "NEITHER" ; end
  def ALLOWED.to_s ; "ALLOWED" ; end
  def DENIED.to_s  ; "DENIED"  ; end
  def NEITHER.to_s ; "NEITHER" ; end

  def DENIED.+(other)
    DENIED
  end

  def ALLOWED.+(other)
    other.denied? ? DENIED : ALLOWED
  end

  def NEITHER.+(other)
    other
  end

  class PolicyDocumentSet

    attr_reader :documents

    def initialize(documents)
      @documents = documents
    end

    def test(context)
      documents.map {|d| d.test(context)}.reduce(DENIED, &:+)
    end

  end

  class PolicyDocument

    attr_reader :version, :sid, :statements

    def initialize(data)
      @version = data["Version"]
      @sid = data["Sid"]
      statements = data["Statement"]
      statements = [ statements ] unless statements.kind_of? Array
      @statements = statements.map {|s| PolicyStatement.new(s)}
    end

    # Note, we default to NEITHER not DENIED because there may be many policy
    # documents to consider for a single request.  See PolicyDocumentSet#test.
    def test(context)
      statements.map {|s| s.test(context)}.reduce(NEITHER, &:+)
    end

  end

  class PolicyStatement

    attr_reader :principal, :action, :notaction, :resource, :notresource, :condition, :effect, :sid

    def initialize(data)
      @data = data
    end

    def test(context)
      if matches?(context)
        case @data["Effect"]
        when "Allow"
          ALLOWED
        when "Deny"
          DENIED
        else
          raise "Unexpected 'Effect': #{self}"
        end
      else
        NEITHER
      end
    end

    def matches?(context)
      return false unless principal_matches?(context)
      return false unless action_matches?(context)
      return false unless resource_matches?(context)
      return false unless conditions_match?(context)
      true
    end

    def principal_matches?(context)
      # Known values of Principal:
      # { "AWS": <arn of a root user> }
      # { "AWS": <arn of an IAM user> }
      # { "AWS": <arn of an IAM role> }
      # { "AWS": <arn of an assumed role> }
      # { "AWS": "AIDA..." } (a user ID)
      # { "AWS": "*" }
      # also "Federated" (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html)
      # { "Service": "whatever.amazonaws.com" }
      # or as above, but with arrays of strings (match any)

      s = @data["Principal"]
      return true if s.nil?

      if s.kind_of? Hash
        case s.keys
        when ["AWS"]
          v = s["AWS"]
          v = [v] unless v.kind_of? Array
          v.include?(context.principal["AWS"]) or (v.include?("*") and context.principal["AWS"])
        when ["Service"]
          v = s["Service"]
          v = [v] unless v.kind_of? Array
          v.include? context.principal["Service"]
        else
          raise "TODO"
        end
      else
        raise "Unexpected Principal: #{self}"
      end
    end

    def action_matches?(context)
      # String, or array of strings
      # simple *-match, case insensitive?
      # Apply Action (any match) / NotAction (none match)
      string_match("Action", "NotAction", context.action, :wildcard_match)
    end

    def resource_matches?(context)
      # String, or array of strings
      # Always either "*", or an arn-string?
      # Apply Resource (any match) / NotResource (none match)
      string_match("Resource", "NotResource", context.resource, :wildcard_match)
    end

    def string_match(positive_list, negative_list, context_value, match_method)
      sym = nil
      if @data[positive_list]
        v = @data[positive_list]
        sym = :any?
      elsif @data[negative_list]
        v = @data[negative_list]
        sym = :none?
      else
        raise "Saw neither #{positive_list} nor #{negative_list} in #{self}"
      end

      v = [ v ] unless v.kind_of? Array

      v.send(sym) do |r|
        send(match_method, r, context_value)
      end
    end

    def wildcard_match(pattern, thing)
      regex = pattern.split(/(\*|\?)/, -1).map do |fragment|
        case fragment
        when "*"
          ".*"
        when "?"
          "."
        else
          Regexp.quote(fragment)
        end
      end.join ""

      not thing.match("^#{regex}$").nil?
    end

    def conditions_match?(context)
      # keys can be multi-valued!

      # { Type: { Key: Value(s) } }
      # Type e.g. StringLike, StringEquals, ArnLike, ArnEquals, ...
      # Key: a key in the context environment
      # All must match

      # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Conditions_String

      # StringEquals, StringNotEquals, StringEqualsIgnoreCase,
      # StringNotEqualsIgnoreCase, StringLike, StringNotLike,

      # NumericEquals, NumericNotEquals, NumericLessThan,
      # NumericLessThanEquals, NumericGreaterThan, NumericGreaterThanEquals,

      # DateEquals, DateNotEquals, DateLessThan, DateLessThanEquals,
      # DateGreaterThan, DateGreaterThanEquals,

      # Bool,

      # IpAddress, NotIpAddress,

      # ArnEquals, ArnNotEquals, ArnLike, ArnNotLike,

      # StringLikeIfExists, (only this one???)

      # Null,

      # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_multi-value-conditions.html
      # ForAllValues:<cond>, ForAnyValue:<cond>

      true
    end

  end

end
