require_relative "../lib/aws_policy_simulator"

describe AwsPolicySimulator do

  describe AwsPolicySimulator::PartialResult do

    it "should provide ALLOWED" do
      v = AwsPolicySimulator::ALLOWED
      expect(v.allowed?).to be_truthy
      expect(v.denied?).to be_falsy
      expect(v.to_s).to match(/ALLOWED/)
      expect(v.inspect).to match(/ALLOWED/)
    end

    it "should provide DENIED" do
      v = AwsPolicySimulator::DENIED
      expect(v.allowed?).to be_falsy
      expect(v.denied?).to be_truthy
      expect(v.to_s).to match(/DENIED/)
      expect(v.inspect).to match(/DENIED/)
    end

    it "should provide NEITHER" do
      v = AwsPolicySimulator::NEITHER
      expect(v.allowed?).to be_falsy
      expect(v.denied?).to be_falsy
      expect(v.to_s).to match(/NEITHER/)
      expect(v.inspect).to match(/NEITHER/)
    end

    it "should add partial results" do
      y = AwsPolicySimulator::ALLOWED
      n = AwsPolicySimulator::DENIED
      p = AwsPolicySimulator::NEITHER

      expect(y).to eq(y)
      expect(y).not_to eq(n)
      expect(y).not_to eq(p)

      expect(n).not_to eq(y)
      expect(n).to eq(n)
      expect(n).not_to eq(p)

      expect(p).not_to eq(y)
      expect(p).not_to eq(n)
      expect(p).to eq(p)

      expect(y + y).to eq(y)
      expect(y + n).to eq(n)
      expect(y + p).to eq(y)

      expect(n + y).to eq(n)
      expect(n + n).to eq(n)
      expect(n + p).to eq(n)

      expect(p + y).to eq(y)
      expect(p + n).to eq(n)
      expect(p + p).to eq(p)
    end

  end

  describe AwsPolicySimulator::PolicyDocumentSet do
    # TODO like PolicyDocument, but defaults to DENIED if nothing matches
  end

  describe AwsPolicySimulator::PolicyDocument do

    def allow_all
      { "Resource" => "*", "Action" => "*", "Effect" => "Allow" }
    end

    def deny_all
      { "Resource" => "*", "Action" => "*", "Effect" => "Deny" }
    end

    def deny_none
      { "NotResource" => "*", "Action" => "*", "Effect" => "Deny" }
    end

    def some_context
      AwsPolicySimulator::RequestContext.new(
        {"AWS" => "arn:aws:iam::123456789012:root"},
        "foo:GetBar",
        "arn:aws:foo:eu-west-1:123456789012:SomeFoo",
      )
    end

    it "should default to neither" do
      doc = AwsPolicySimulator::PolicyDocument.new({"Version" => "2012-10-17", "Statement" => []})
      ctx = some_context
      ans = doc.test(ctx)
      expect(ans).to eq(AwsPolicySimulator::NEITHER)
    end

    it "should apply Deny" do
      doc = AwsPolicySimulator::PolicyDocument.new({"Version" => "2012-10-17", "Statement" => [allow_all,deny_all,allow_all]})
      ctx = some_context
      ans = doc.test(ctx)
      expect(ans).to eq(AwsPolicySimulator::DENIED)
    end

    it "should apply Allow" do
      doc = AwsPolicySimulator::PolicyDocument.new({"Version" => "2012-10-17", "Statement" => [deny_none,allow_all,deny_none]})
      ctx = some_context
      ans = doc.test(ctx)
      expect(ans).to eq(AwsPolicySimulator::ALLOWED)
    end

    it "should handle a bare statement" do
      doc = AwsPolicySimulator::PolicyDocument.new({"Version" => "2012-10-17", "Statement" => allow_all})
      ctx = some_context
      ans = doc.test(ctx)
      expect(ans).to eq(AwsPolicySimulator::ALLOWED)
    end

    describe "Principal" do

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

    describe "Resource / NotResource" do

      it "blah" do
        true
      end

    end

    describe "Action / NotAction" do

      it "blah" do
        true
      end

    end

    describe "Conditions" do

      it "blah" do
        true
      end

    end

  end

end
