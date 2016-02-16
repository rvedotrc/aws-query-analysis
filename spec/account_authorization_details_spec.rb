require_relative "../lib/account_authorization_details"

require 'json'

describe AccountAuthorizationDetails do

  FIXTURE = File.expand_path("account-authorization-details.json", File.dirname(__FILE__))
  DATA = JSON.parse(IO.read FIXTURE)

  def get_report
    AccountAuthorizationDetails::Report.new(DATA)
  end

  describe AccountAuthorizationDetails::Report do

    it "can load from a filename" do
      report = AccountAuthorizationDetails::Report.new(FIXTURE)
      expect(report.roles.count > 100).to be_truthy
    end

    it "can load from a data structure" do
      report = AccountAuthorizationDetails::Report.new(DATA)
      expect(report.roles.count > 100).to be_truthy
    end

    it "exposes users" do
      expect(get_report.users.count).to be > 10
    end

    it "exposes groups" do
      expect(get_report.groups.count).to be > 10
    end

    it "exposes roles" do
      expect(get_report.roles.count).to be > 10
    end

    it "exposes policies" do
      expect(get_report.policies.count).to be > 10
    end

    it "exposes user_by_name" do
      name = "modav.Rachel_Evans"
      thing = get_report.user_by_name(name)
      expect(thing).not_to be_nil
      expect(thing.data["UserName"]).to eq(name)
    end

    it "exposes group_by_name" do
      name = "247"
      thing = get_report.group_by_name(name)
      expect(thing).not_to be_nil
      expect(thing.data["GroupName"]).to eq(name)
    end

    it "exposes role_by_name" do
      name = "Rachel_Evans"
      thing = get_report.role_by_name(name)
      expect(thing).not_to be_nil
      expect(thing.data["RoleName"]).to eq(name)
    end

    it "exposes policy_by_name" do
      name = "247.read-only"
      thing = get_report.policy_by_name(name)
      expect(thing).not_to be_nil
      expect(thing.data["PolicyName"]).to eq(name)
    end

  end

  describe "user" do

    it "should expose groups" do
      user = get_report.user_by_name("foxk13")
      expect(user.groups).to be_kind_of Array
      expect(user.groups.first).to be_kind_of AccountAuthorizationDetails::Group
    end

    it "should expose managed_policies" do
      user = get_report.user_by_name("modav.Rachel_Evans")
      expect(user.managed_policies).to be_kind_of Array
      expect(user.managed_policies.first).to be_kind_of AccountAuthorizationDetails::ManagedPolicy
    end

    it "should expose inline_policies" do
      user = get_report.user_by_name("rachel-process-virgin-email")
      expect(user.inline_policies).to be_kind_of Array
      expect(user.inline_policies.first).to be_kind_of AccountAuthorizationDetails::InlinePolicy
    end

  end

  describe "group" do

    it "should expose managed_policies" do
      group = get_report.group_by_name("247")
      expect(group.managed_policies).to be_kind_of Array
      expect(group.managed_policies.first).to be_kind_of AccountAuthorizationDetails::ManagedPolicy
    end

    it "should expose inline_policies" do
      group = get_report.group_by_name("TestModavGtiResources-TranscodeGroup-C1E3SRCE73UD")
      expect(group.inline_policies).to be_kind_of Array
      expect(group.inline_policies.first).to be_kind_of AccountAuthorizationDetails::InlinePolicy
    end

  end

  describe "role" do

    it "should expose managed_policies" do
      role = get_report.role_by_name("Rachel_Evans")
      expect(role.managed_policies).to be_kind_of Array
      expect(role.managed_policies.first).to be_kind_of AccountAuthorizationDetails::ManagedPolicy
    end

    it "should expose inline_policies" do
      role = get_report.role_by_name("Rachel_Evans")
      expect(role.inline_policies).to be_kind_of Array
      expect(role.inline_policies.first).to be_kind_of AccountAuthorizationDetails::InlinePolicy
    end

  end

  describe "inline_policies" do

    it "should expose policy_name and policy_document" do
      role = get_report.role_by_name("Rachel_Evans")
      policy = role.inline_policies.first
      expect(policy).to be_kind_of AccountAuthorizationDetails::InlinePolicy
      expect(policy.policy_name).to eq("ChangeCorrespondingUsersPasswordAndMFA")
      expect(policy.policy_document["Statement"]).to be_kind_of Array
    end

  end

  describe "managed_policies" do

    it "should expose policy_name and policy_document" do
      role = get_report.role_by_name("Rachel_Evans")
      policy = role.managed_policies.first
      expect(policy).to be_kind_of AccountAuthorizationDetails::ManagedPolicy
      expect(policy.policy_name).to eq("modav.modav-dev")
      expect(policy.policy_document["Statement"]).to be_kind_of Array
    end

  end

end
