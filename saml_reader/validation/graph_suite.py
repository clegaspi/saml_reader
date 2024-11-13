"""
These classes implement a graph-based approach to running a battery of validation tests
where one test can depend on the pass/fail state of another test.
"""

import networkx as nx

"""Test completion states"""
TEST_PASS = 1
TEST_FAIL = 0
TEST_NOT_RUN = -1


class TestDefinition:
    """
    Defines a single validation test to be run, ideally run as part of a suite.
    """

    def __init__(self, title, test_function, dependencies=None, required_context=None):
        """
        Construct a validation test.

        Args:
            title (basestring): The name of the test. This must be unique across tests
                that are a part of a suite.
            test_function (callable): A function which must take one argument (a dict) that
                contains context data required for running the test. It must return at least one
                value, which will be cast as a boolean to determine pass/fail. If multiple values
                are returned, the first value will be used to determine the test result, and the
                rest will be stored and can be retrieved with `get_result_metadata()`.
            dependencies (`iterable` of `basestring`, `TestDefinition` or `tuple`, optional): an iterable
                containing test titles (as strings), test definitions (as `TestDefinition`), or
                two-member tuples, where the first element is a title or test definition and the
                second element is the required outcome of that test (TEST_PASS or TEST_FAIL).
                For titles and definitions, the default required outcome is TEST_PASS. Default: None.
            required_context (`iterable` of `basestring`, optional): an iterable containing names of keys expected
                by the test in the context data. Default: None.
        """
        self.status = TEST_NOT_RUN
        self.dependencies = dict()

        # Assign required results for dependencies
        for dependency in dependencies or []:
            if isinstance(dependency, (str, TestDefinition)):
                self.dependencies[dependency] = TEST_PASS
            elif isinstance(dependency, tuple):
                if len(dependency) != 2:
                    raise ValueError(
                        "Dependency must be a 2-length tuple, str, or TestDefinition"
                    )
                test, required_result = dependency
                if required_result not in (TEST_PASS, TEST_FAIL):
                    raise ValueError("Dependency result must be TEST_PASS or TEST_FAIL")
                self.dependencies[test] = required_result

        self.title = title or ""
        self.required_context = set(required_context) if required_context else set()

        if not callable(test_function):
            raise ValueError("test_function not a callable object")
        self._func = test_function

        self._result_metadata = None

    def add_dependency(self, dependency, required_result=TEST_PASS):
        """
        Add single test dependency and the required result.

        Args:
            dependency (`basestring` or `TestDefinition`): Test object or test
                name that this test depends on
            required_result (int, optional): Whether the dependent test should pass (1, TEST_PASS)
                or fail (0, TEST_FAIL) to meet the dependency requirement. Default: TEST_PASS
        """
        self.dependencies[dependency] = required_result

    def remove_dependency(self, dependency):
        """
        Remove single test dependency, if it exists as a dependency.

        Args:
            dependency (`basestring` or `TestDefinition`): Test object or test
                name to remove.
        """
        if dependency in self.dependencies:
            self.dependencies.pop(dependency)

    def add_required_context_value(self, context):
        """
        Add single context variable required for the test.

        Args:
            context (basestring): Name of variable to include in
                context data passed to function.
        """
        self.required_context.add(context)

    def remove_required_context_value(self, context):
        """
        Remove single required context variable, if it exists.

        Args:
            context (basestring): Name of context variable to remove
        """
        if context in self.required_context:
            self.required_context.remove(context)

    def run(self, context=None):
        """
        Run the test function with the provided context variables.

        Args:
            context (dict, optional): Context values required for the test.

        Returns:
            (bool) result of the test

        Raises:
            (ValueError) if provided context does not match expected context
        """
        # Check provided context to ensure it has all required values
        if self.required_context:
            if not context:
                raise ValueError("No context provided when context values required")
            if any(x not in context for x in self.required_context):
                missing_context = (
                    self.required_context
                    - self.required_context.intersection(set(context.keys()))
                )
                raise ValueError(f"Missing context values for test: {missing_context}")

        # Run the test with required context
        result = self._func({x: context[x] for x in self.required_context})

        # Assess result
        if isinstance(result, tuple):
            self.status = int(bool(result[0]))
            self._result_metadata = result[1:]
        else:
            self.status = int(bool(result))
        return self.status

    def get_result_metadata(self):
        """
        Retrieves the metadata returned by the completed test.

        Returns:
            (tuple) stored metadata returned by test. None if no metadata returned.
        """
        return self._result_metadata

    def __eq__(self, other):
        """
        Equality with strings and other `TestDefinition` objects, by comparing title.

        Args:
            other (`basestring` or `TestDefinition`): value to compare

        Returns:
            (bool) True if matching titles, False otherwise

        Raises:
            (NotImplemented) if type of `other` is not one of types listed
        """
        if isinstance(other, str):
            return self.title == other
        elif isinstance(other, TestDefinition):
            return self.title == other.title
        raise NotImplemented

    def __hash__(self):
        return hash(self.title)

    def __str__(self):
        return self.title

    def __repr__(self):
        return self.title


class _FailedTest(TestDefinition):
    """
    Internal class to block advancement of graph traversal when a test depends on
    the failure of another test, and that test passes. Fails automatically when run
    to block advancement.
    """

    def __init__(self, test_to_monitor):
        """
        Create a blocker node for required test failures.

        Args:
            test_to_monitor (`basestring` or `TestDefinition`): test to monitor
                (value is rather inconsequential to operation)
        """
        super().__init__(
            f"Blocker for tests depending on failure of: {test_to_monitor}",
            lambda x: TEST_FAIL,
            dependencies=[test_to_monitor],
        )


class TestSuite:
    """
    A collection of tests to run as a group. Manages test dependencies.
    """

    def __init__(self):
        """
        Construct the suite.
        """
        self._tests = set()
        self._context = dict()
        self._test_graph = None
        self._results = None
        self._has_run = False

    def context_satisfies_requirements(self):
        """
        Checks if provided context satisfies the requirements of all tests
        in the suite.

        Returns:
            (bool) True if all context requirements are satisfied, and False otherwise
        """
        return all(
            context_value in self._context
            for test in self._tests
            for context_value in test.required_context
        )

    def all_dependent_test_in_suite(self):
        """
        Checks if every test in the suite has its dependent tests in the suite.

        Returns:
            (bool) True if all dependency tests are in the suite, and False otherwise
        """
        return all(
            dependency in self._tests
            for test in self._tests
            for dependency in test.dependencies.keys()
        )

    def add_test(self, test, replace=True):
        """
        Add a test to the suite.

        Args:
            test (TestDefinition): Test object to add to the suite
            replace (bool, optional): if True, replace the test if it exists. False will
                raise a ValueError if a test with the same name is in the suite.

        Raises:
            (ValueError) if test with same title exists in the suite and `replace=False`

        """
        if not replace and test in self._tests:
            raise ValueError(f"Suite already contains test '{test.title}'")
        self._tests.add(test)

    def remove_test(self, test):
        """
        Remove test from suite if it exists.

        Args:
            test (`basestring` or `TestDefinition`): title or test object to
                remove from suite
        """
        if test in self._tests:
            self._tests.remove(test)

    def get_context(self):
        """
        Get the context values for the test suite that will be passed to each
        test.

        Returns:
            (dict) context values, keyed by context variable names. Empty dict if none.
        """
        return self._context or dict()

    def set_context(self, context):
        """
        Set the context values for the test suite that will be passed to each
        test.

        Args:
            context (dict): context values, keyed by context variable names
        """
        self._context = context

    def run(self):
        """
        Run the test suite with the given context.

        Raises:
            (ValueError) if context or dependencies are not satisfied
        """
        if not self.context_satisfies_requirements():
            raise ValueError("Context is missing required values for tests")
        if not self.all_dependent_test_in_suite():
            raise ValueError("Dependency test missing")

        self._build_graph()
        self._run_suite()
        self._has_run = True

    def _build_graph(self):
        """
        Builds directional graph of tests for traversal.
        Nodes are tests and edges are dependencies.
        """

        self._test_graph = nx.DiGraph()

        # Load all tests as nodes
        for test in self._tests:
            node_name = "PASS_" + test.title
            self._test_graph.add_node(node_name, test_object=test)

        # Create edges based on dependencies
        for test in self._tests:
            for dependency, required_result in test.dependencies.items():
                child_node_name = "PASS_" + test.title
                if required_result == TEST_PASS:
                    parent_node_name = "PASS_" + str(dependency)
                elif required_result == TEST_FAIL:
                    # If a test requires that another test fail,
                    # create an interim node to block traversal if the
                    # dependent test passes. This node will be removed if
                    # the dependent test fails to allow child tests to run.
                    parent_node_name = "FAIL_" + str(dependency)
                    self._test_graph.add_node(
                        parent_node_name, test_object=_FailedTest(dependency)
                    )
                    # Draw edge from dependent test to blocking node
                    self._test_graph.add_edge(
                        "PASS_" + str(dependency), parent_node_name
                    )
                else:
                    raise ValueError("Invalid required test result!")
                # Draw edge from dependent test (or blocking node) to current test
                self._test_graph.add_edge(parent_node_name, child_node_name)

    def _run_suite(self):
        """
        Run tests and record results.
        """
        for test in self._get_next_test():
            # print(f"Running test {test.title}")
            test.run(self._context)
            # print(f"Test: {test.title}, Result: {test.status}")

        self._results = {test: test.status for test in self._tests}

    def _get_next_test(self):
        """
        Traverses graph recursively and generates tests to run. As tests pass,
        the nodes are removed from the graph.

        Yields:
            (TestDefinition) test to run
        """

        def __yield_tests_rec(graph):
            queue_for_removal = set()
            # Traverse all nodes by all inbound edges in the current view of the graph
            for test_name, n_unmet_dependencies in graph.in_degree:
                test_object = graph.nodes[test_name]["test_object"]
                if n_unmet_dependencies == 0 and test_object.status == TEST_NOT_RUN:
                    # If there are no unmet dependencies (presence of no inbound edges)
                    # and the test hasn't been run, then send it up to be run.
                    yield test_object

                    if test_object.status == TEST_PASS:
                        # If test passes, queue node for removal on next pass
                        queue_for_removal.add(test_name)
                    elif test_object.status == TEST_FAIL:
                        # If test fails, queue the related blocker node to be removed on next pass (if exists)
                        queue_for_removal.add("FAIL_" + str(test_object))
                    else:
                        raise ValueError("Invalid test result")

            # Exit criterion: if no tests ran, process is finished
            if not queue_for_removal:
                return
            # Delete queued nodes from graph
            graph.remove_nodes_from(queue_for_removal)
            # Clear queue to save memory
            queue_for_removal.clear()
            # Recurse on new view of graph
            # TODO: consider not using recursion as it could get hit recursion depth limit if many
            #       rounds of testing have to be done
            yield from __yield_tests_rec(graph)

        # Begin recursion
        yield from __yield_tests_rec(self._test_graph)

    def has_run(self):
        """
        Returns if suite has been run or not.

        Returns:
            (bool) True if suite has run, False otherwise
        """
        return self._has_run

    def get_results(self):
        """
        Outputs the results of the tests.

        Returns:
            (dict) test results, keyed by test title. 0 = TEST_FAIL, 1 = TEST_PASS, -1 = TEST_NOT_RUN
        """
        if self.has_run():
            return {k.title: v for k, v in self._results.items()}
        raise ValueError("Test suite not run!")
