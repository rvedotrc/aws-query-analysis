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

  class PolicyDocument

    attr_reader :version, :sid, :statements

    def initialize(data)
      @version = data["Version"]
      @sid = data["Sid"]
      statements = data["Statement"]
      statements = [ statements ] unless @statements.kind_of? Array
      @statements = statements.map {|s| PolicyStatement.new(s)}
    end

    def test(context)
      statements.map {|s| s.test(context)}.reduce(&:+) + PartialResult::NEITHER
    end

  end

  class PolicyStatement

    attr_reader :principal, :action, :notaction, :resource, :notresource, :condition, :effect, :sid

    def initialize(data)
      @data = data
    end

    def test(context)
      if matches?(context)
        case data["Effect"]
        when "Allow"
          PartialResult::ALLOWED
        when "Deny"
          PartialResult::DENIED
        end
      else
        PartialResult::NEITHER
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
    end

    def action_matches?(context)
      # String, or array of strings
      # simple *-match, case insensitive?
      # Apply Action (any match) / NotAction (none match)
    end

    def resource_matches?(context)
      # String, or array of strings
      # Always either "*", or an arn-string?
      # Apply Resource (any match) / NotResource (none match)
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

    end

  end

end
