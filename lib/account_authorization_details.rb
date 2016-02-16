module AccountAuthorizationDetails

  class Report

    attr_reader :data

    def initialize(data)
      if data.kind_of? String
        require 'json'
        data = JSON.parse(IO.read data)
      end
      @data = data
    end

    def users
      data["UserDetailList"].map {|d| User.new(self, d) }
    end

    def user_by_name(n)
      users.find {|u| u.data["UserName"] == n}
    end

    def groups
      data["GroupDetailList"].map {|d| Group.new(self, d) }
    end

    def group_by_name(n)
      groups.find {|g| g.data["GroupName"] == n}
    end

    def roles
      data["RoleDetailList"].map {|d| Role.new(self, d) }
    end

    def role_by_name(n)
      roles.find {|r| r.data["RoleName"] == n}
    end

    def policies
      data["Policies"].map {|d| ManagedPolicy.new(self, d) }
    end

    def policy_by_name(n)
      policies.find {|g| g.data["PolicyName"] == n}
    end

  end

  class User

    attr_reader :report, :data

    def initialize(report, data)
      @report = report
      @data = data
    end

    def groups
      data["GroupList"].map {|n| report.group_by_name(n) }
    end

    def managed_policies
      data["AttachedManagedPolicies"].map {|att| report.policy_by_name(att["PolicyName"]) }
    end

    def inline_policies
      data["UserPolicyList"].map {|inline| InlinePolicy.new(self, inline) }
    end

    def to_s
      "<User #{data["UserName"].inspect}>"
    end

    def inspect
      "<User @data=#{data.inspect}>"
    end

  end

  class Group

    attr_reader :report, :data

    def initialize(report, data)
      @report = report
      @data = data
    end

    def managed_policies
      data["AttachedManagedPolicies"].map {|att| report.policy_by_name(att["PolicyName"]) }
    end

    def inline_policies
      data["GroupPolicyList"].map {|inline| InlinePolicy.new(self, inline) }
    end

    def to_s
      "<Group #{data["GroupName"].inspect}>"
    end

    def inspect
      "<Group @data=#{data.inspect}>"
    end

  end

  class Role

    attr_reader :report, :data

    def initialize(report, data)
      @report = report
      @data = data
    end

    def managed_policies
      data["AttachedManagedPolicies"].map {|att| report.policy_by_name(att["PolicyName"]) }
    end

    def inline_policies
      data["RolePolicyList"].map {|inline| InlinePolicy.new(self, inline) }
    end

    def to_s
      "<Role #{data["RoleName"].inspect}>"
    end

    def inspect
      "<Role @data=#{data.inspect}>"
    end

  end

  class InlinePolicy

    attr_reader :parent, :data

    def initialize(parent, data)
      @parent = parent
      @data = data
    end

    def policy_name
      data["PolicyName"]
    end

    def policy_document
      data["PolicyDocument"]
    end

    def to_s
      "<InlinePolicy #{policy_name.inspect}>"
    end

    def inspect
      "<InlinePolicy @data=#{data.inspect}>"
    end

  end

  class ManagedPolicy

    attr_reader :parent, :data

    def initialize(parent, data)
      @parent = parent
      @data = data
    end

    def policy_name
      data["PolicyName"]
    end

    def policy_document
      data["PolicyVersionList"].find {|pv| pv["IsDefaultVersion"]}["Document"]
    end

    def to_s
      "<ManagedPolicy #{policy_name.inspect}>"
    end

    def inspect
      "<ManagedPolicy @data=#{data.inspect}>"
    end

  end

end
