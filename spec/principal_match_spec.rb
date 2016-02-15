require_relative "../lib/aws_policy_simulator"

describe "match on Principal" do

  def context_for_principal(principal)
    AwsPolicySimulator::RequestContext.new(
      principal,
      "foo:GetBar",
      "arn:aws:foo:eu-west-1:123456789012:SomeFoo",
    )
  end

  def a_root_user
    { "AWS" => "arn:aws:iam::123456789012:root" }
  end

  def an_iam_user
    { "AWS" => "arn:aws:iam::123456789012:user/someone" }
  end

  def an_iam_role
    { "AWS" => "arn:aws:iam::123456789012:role/something" }
  end

  def a_service(s = "ec2")
    { "Service" => "#{s}.amazonaws.com" }
  end

  def some_services(list)
    { "Service" => list.map {|s| "#{s}.amazonaws.com"} }
  end

  def expect_match(context_principal, statement_principal)
    expect_result(context_principal, statement_principal, AwsPolicySimulator::ALLOWED)
  end

  def expect_no_match(context_principal, statement_principal)
    expect_result(context_principal, statement_principal, AwsPolicySimulator::NEITHER)
  end

  def expect_result(context_principal, statement_principal, result)
    s = { "Effect" => "Allow", "Resource" => "*" }
    s["Principal"] = statement_principal unless statement_principal.nil?
    doc = AwsPolicySimulator::PolicyDocument.new({"Version" => "2012-10-17", "Statement" => [s]})

    ctx = context_for_principal(context_principal)

    ans = doc.test(ctx)
    expect(ans).to eq(result)
  end

  it "defaults to matching" do
    expect_match(a_root_user, nil)
    expect_match(an_iam_user, nil)
    expect_match(an_iam_role, nil)
    expect_match(a_service, nil)
  end

  it "matches AWS *" do
    t = { "AWS" => "*" }
    expect_match(a_root_user, t)
    expect_match(an_iam_user, t)
    expect_match(an_iam_role, t)
    expect_no_match(a_service, t) # Is this right?
  end

  it "matches AWS (single)" do
    # TODO, Supports wildcards?
    t = an_iam_user
    expect_no_match(a_root_user, t)
    expect_match(an_iam_user, t)
    expect_no_match(an_iam_role, t)
    expect_no_match(a_service, t)
  end

  it "matches AWS (list)" do
    # TODO, Supports wildcards?
    t = { "AWS" => [ an_iam_user["AWS"], an_iam_role["AWS"] ] }
    expect_no_match(a_root_user, t)
    expect_match(an_iam_user, t)
    expect_match(an_iam_role, t)
    expect_no_match(a_service, t)
  end

  it "matches a service" do
    t = a_service
    expect_no_match(a_root_user, t)
    expect_no_match(an_iam_user, t)
    expect_no_match(an_iam_role, t)
    expect_match(a_service, t)
  end

  it "matches a list of services" do
    t = some_services(%w[ ec2 sns sqs ])
    expect_no_match(a_root_user, t)
    expect_no_match(an_iam_user, t)
    expect_no_match(an_iam_role, t)
    expect_match(a_service("sqs"), t)
    expect_no_match(a_service("rds"), t)
  end

end
